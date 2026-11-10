"""Клиентские сценарии стенда.

Каждая функция подключается к записывающему прокси соответствующего
сервиса и выполняет типовые действия администратора или пользователя
корпоративной сети. Функции возвращают краткое текстовое описание
выполненных действий для журнала стенда.
"""

from __future__ import annotations

import base64
import http.client
import io
import os
import socket
import ssl
import uuid

from . import config, psrp, wsman
from .servers import rdp

H = config.LOCALHOST
SECRET_TEXT = "Конфиденциально: пароль от резервного сервера Backup#2026"


def _basic_auth() -> str:
    """Значение заголовка Authorization для обычной (Basic) аутентификации."""
    raw = f"{config.DOMAIN}\\{config.USERNAME}:{config.PASSWORD}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _http(service: config.Service, tls_ctx: ssl.SSLContext | None) -> http.client.HTTPConnection:
    """Открывает HTTP- или HTTPS-соединение к прокси сервиса."""
    if service.tls:
        return http.client.HTTPSConnection(H, service.proxy_port, context=tls_ctx, timeout=10)
    return http.client.HTTPConnection(H, service.proxy_port, timeout=10)


def _request(conn: http.client.HTTPConnection, method: str, url: str, body: bytes | str = b"",
             headers: dict[str, str] | None = None, host: str = "dc01.lab.local") -> tuple[int, bytes]:
    """Выполняет HTTP-запрос в рамках постоянного соединения и читает ответ."""
    hdrs = {"Host": host, "User-Agent": "Microsoft-WebDAV-MiniRedir/10.0.19045"}
    hdrs.update(headers or {})
    conn.request(method, url, body=body.encode() if isinstance(body, str) else body, headers=hdrs)
    resp = conn.getresponse()
    return resp.status, resp.read()


# --------------------------------------------------------------------------
# SMB
# --------------------------------------------------------------------------

def smb_scenario(service: config.Service) -> str:
    """Подключение к общему ресурсу, загрузка и чтение файла по SMB2."""
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT  # noqa: F401  (импорт для регистрации диалектов)
    from impacket.smb3structs import SMB2_DIALECT_21

    conn = SMBConnection("DC01", H, sess_port=service.proxy_port, preferredDialect=SMB2_DIALECT_21)
    conn.login(config.USERNAME, config.PASSWORD, config.DOMAIN)
    shares = [s["shi1_netname"][:-1] for s in conn.listShares()]
    conn.putFile("LAB", "\\secret.txt", io.BytesIO(SECRET_TEXT.encode("utf-8")).read)
    buf = io.BytesIO()
    conn.getFile("LAB", "\\secret.txt", buf.write)
    files = [f.get_longname() for f in conn.listPath("LAB", "\\*")]
    conn.logoff()
    conn.close()
    return f"ресурсы {shares}, файлы {files}, прочитано {len(buf.getvalue())} байт"


# --------------------------------------------------------------------------
# WebDAV
# --------------------------------------------------------------------------

def webdav_scenario(service: config.Service, tls_ctx: ssl.SSLContext | None) -> str:
    """Типовая сессия мини-редиректора WebDAV: OPTIONS, PROPFIND, MKCOL, PUT, GET, LOCK."""
    conn = _http(service, tls_ctx)
    auth = {"Authorization": _basic_auth()}
    codes = []
    codes.append(_request(conn, "OPTIONS", "/")[0])
    codes.append(_request(conn, "PROPFIND", "/", headers={"Depth": "0"})[0])  # без пароля -> 401
    propfind = ('<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop>'
                "<D:resourcetype/><D:getcontentlength/><D:getlastmodified/></D:prop></D:propfind>")
    codes.append(_request(conn, "PROPFIND", "/", propfind,
                          {**auth, "Depth": "1", "Content-Type": "text/xml"})[0])
    codes.append(_request(conn, "MKCOL", "/Reports/", headers=auth)[0])
    codes.append(_request(conn, "PUT", "/Reports/salary.txt", SECRET_TEXT.encode("utf-8"),
                          {**auth, "Content-Type": "text/plain; charset=utf-8"})[0])
    lock = ('<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope>'
            "<D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>"
            f"<D:owner><D:href>{config.DOMAIN}\\{config.USERNAME}</D:href></D:owner></D:lockinfo>")
    codes.append(_request(conn, "LOCK", "/Reports/salary.txt", lock,
                          {**auth, "Content-Type": "text/xml", "Timeout": "Second-3600"})[0])
    codes.append(_request(conn, "GET", "/Reports/salary.txt", headers=auth)[0])
    codes.append(_request(conn, "PROPFIND", "/Reports/", propfind,
                          {**auth, "Depth": "1", "Content-Type": "text/xml"})[0])
    codes.append(_request(conn, "DELETE", "/Reports/salary.txt", headers=auth)[0])
    codes.append(_request(conn, "DELETE", "/Reports/", headers=auth)[0])
    conn.close()
    return f"коды ответов {codes}"


# --------------------------------------------------------------------------
# LDAP
# --------------------------------------------------------------------------

def ldap_scenario(service: config.Service, tls_ctx: ssl.SSLContext | None, mode: str) -> str:
    """Простая привязка (simple bind) и поиск в каталоге.

    Аргументы:
        mode: 'plain' – открытый LDAP, 'starttls' – переход на TLS командой
              StartTLS перед привязкой, 'ldaps' – TLS с момента подключения.
    """
    import ldap3

    tls = ldap3.Tls(validate=ssl.CERT_NONE) if mode != "plain" else None
    if tls_ctx is not None and tls_ctx.keylog_filename:
        # ldap3 создаёт контекст TLS через ssl.create_default_context(), который
        # записывает сеансовые ключи в файл из переменной окружения SSLKEYLOGFILE.
        os.environ["SSLKEYLOGFILE"] = tls_ctx.keylog_filename
    server = ldap3.Server(H, port=service.proxy_port, use_ssl=(mode == "ldaps"), tls=tls,
                          get_info=ldap3.NONE)
    conn = ldap3.Connection(server, user=config.USER_DN, password=config.PASSWORD,
                            authentication=ldap3.SIMPLE, auto_bind=False, raise_exceptions=False)
    conn.open()
    if mode == "starttls":
        conn.start_tls()
    conn.bind()
    conn.search(config.BASE_DN, "(&(objectClass=user)(sAMAccountName=*))", ldap3.SUBTREE,
                attributes=["sAMAccountName", "displayName", "mail", "memberOf", "title"])
    found = [str(e.entry_dn) for e in conn.entries]
    conn.search(config.BASE_DN, "(objectClass=computer)", ldap3.SUBTREE,
                attributes=["dNSHostName", "operatingSystem"])
    found += [str(e.entry_dn) for e in conn.entries]
    conn.unbind()
    os.environ.pop("SSLKEYLOGFILE", None)
    return f"режим {mode}: найдено записей {len(found)}"


# --------------------------------------------------------------------------
# WinRM / WMI / PSRP
# --------------------------------------------------------------------------

def winrm_scenario(service: config.Service, tls_ctx: ssl.SSLContext | None) -> str:
    """Сеанс WinRM: Identify, запрос WMI через WS-Man и выполнение команд PowerShell."""
    conn = _http(service, tls_ctx)
    port = service.virtual_port
    scheme = "https" if service.tls else "http"
    to = f"{scheme}://dc01.lab.local:{port}/wsman"
    hdr = {"Authorization": _basic_auth(), "Content-Type": "application/soap+xml;charset=UTF-8",
           "User-Agent": "Microsoft WinRM Client"}

    def post(xml: str) -> bytes:
        """Отправляет SOAP-конверт на /wsman и возвращает тело ответа."""
        status, body = _request(conn, "POST", "/wsman", xml.replace("http://dc01.lab.local:5985/wsman", to),
                                hdr, host=f"dc01.lab.local:{port}")
        if status != 200:
            raise RuntimeError(f"WinRM вернул код {status}")
        return body

    post(wsman.identify())
    # WMI поверх WinRM: перечисление экземпляров Win32_OperatingSystem.
    import re
    enum = post(wsman.enumerate_wmi()).decode()
    ctx = re.search(r"<n:EnumerationContext>([^<]+)<", enum).group(1)
    post(wsman.pull(ctx))
    # PowerShell Remoting: создание пула, запуск команд, получение вывода.
    rpid = uuid.uuid4()
    creation = psrp.encode_messages([
        psrp.build_message(psrp.DEST_SERVER, psrp.SESSION_CAPABILITY, rpid, None, psrp.session_capability()),
        psrp.build_message(psrp.DEST_SERVER, psrp.INIT_RUNSPACEPOOL, rpid, None, psrp.init_runspacepool()),
    ])
    shell_resp = post(wsman.create_shell(creation)).decode()
    shell_id = re.search(r'Name="ShellId">([^<]+)<', shell_resp).group(1)
    post(wsman.receive(shell_id, "").replace(' CommandId=""', ""))
    commands = ["whoami", "Get-Service WinRM",
                f"net user backup_admin {config.PASSWORD}! /add /domain"]
    for i, script in enumerate(commands, start=10):
        pid = str(uuid.uuid4()).upper()
        args = psrp.encode_messages([psrp.build_message(psrp.DEST_SERVER, psrp.CREATE_PIPELINE, rpid,
                                                        uuid.UUID(pid), psrp.create_pipeline(script))], i)
        post(wsman.command(shell_id, pid, args))
        post(wsman.receive(shell_id, pid))
    post(wsman.delete_shell(shell_id))
    conn.close()
    return f"выполнено команд PowerShell: {len(commands)}"


# --------------------------------------------------------------------------
# RDP
# --------------------------------------------------------------------------

def rdp_scenario(service: config.Service, tls_ctx: ssl.SSLContext) -> str:
    """Начальная фаза подключения RDP с переходом на TLS."""
    sock = socket.create_connection((H, service.proxy_port), timeout=10)
    sock.sendall(rdp.connection_request(config.USERNAME,
                                        rdp.PROTOCOL_SSL | rdp.PROTOCOL_HYBRID | rdp.PROTOCOL_HYBRID_EX))
    confirm = rdp.read_tpkt(sock)
    selected = int.from_bytes(confirm[-4:], "little")
    tls = tls_ctx.wrap_socket(sock, server_hostname="dc01.lab.local")
    # Упрощённое MCS Connect Initial: имя клиентского компьютера в UTF-16LE.
    client_name = "WS01-STUDENT".encode("utf-16-le").ljust(32, b"\x00")
    tls.sendall(rdp.tpkt(b"\x02\xf0\x80\x7f\x65\x82\x00\x30" + client_name + bytes(16)))
    rdp.read_tpkt(tls)
    try:
        tls.unwrap()
    except (ssl.SSLError, OSError):
        pass
    tls.close()
    return f"сервер выбрал протокол безопасности 0x{selected:x}"


# --------------------------------------------------------------------------
# WMI через DCOM/RPC
# --------------------------------------------------------------------------

def wmi_dcom_scenario(service: config.Service) -> str:
    """Начальная фаза WMI через DCOM: обращение к службе RPC хоста (порт 135).

    Выполняются два шага, с которых начинается любое удалённое подключение
    WMI по DCOM: привязка к интерфейсу IObjectExporter и вызов ServerAlive2
    (возвращает сетевые адреса сервера), затем запрос к сопоставителю
    конечных точек (Endpoint Mapper) о динамическом порту службы.
    Аутентификация не требуется, поэтому сценарий безопасен для хоста.
    """
    from impacket.dcerpc.v5 import epm, transport
    from impacket.dcerpc.v5.dcomrt import IObjectExporter, IID_IObjectExporter

    binding = f"ncacn_ip_tcp:{H}[{service.proxy_port}]"
    rpc = transport.DCERPCTransportFactory(binding)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(IID_IObjectExporter)
    bindings = IObjectExporter(dce).ServerAlive2()
    dce.disconnect()

    rpc = transport.DCERPCTransportFactory(binding)
    dce = rpc.get_dce_rpc()
    dce.connect()  # привязку к интерфейсу EPM выполняет hept_map
    # Запрос динамического порта службы планировщика заданий (MS-TSCH),
    # которая, как и WMI, зарегистрирована в сопоставителе конечных точек.
    from impacket.dcerpc.v5 import tsch
    try:
        port = epm.hept_map(H, tsch.MSRPC_UUID_TSCHS, protocol="ncacn_ip_tcp", dce=dce)
    except Exception as exc:  # служба может быть не зарегистрирована в EPM
        port = f"нет ({exc.__class__.__name__})"
    dce.disconnect()
    return f"ServerAlive2: {len(bindings)} сетевых привязок; конечная точка MS-TSCH: {port}"
