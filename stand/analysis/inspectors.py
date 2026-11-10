"""Анализаторы прикладных протоколов.

Каждая функция inspect_* получает собранный TCP-поток и заполняет отчёт
StreamReport: типы сообщений, параметры защиты и находки – сведения,
которые может получить сторонний наблюдатель, перехвативший трафик.
"""

from __future__ import annotations

import base64
import re
import struct
import uuid

from .. import ber, psrp
from ..servers.ldap_server import OPS as LDAP_OPS, STARTTLS_OID
from .model import HIGH, INFO, MEDIUM, StreamReport, preview
from .streams import Stream

# ==========================================================================
# TLS
# ==========================================================================

TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
}


def is_tls(data: bytes) -> bool:
    """Проверяет, начинаются ли данные с записи TLS Handshake."""
    return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03 and data[2] <= 0x04


def _extensions(body: bytes, pos: int) -> dict[int, bytes]:
    """Разбирает блок расширений ClientHello/ServerHello."""
    exts = {}
    if pos + 2 > len(body):
        return exts
    end = pos + 2 + struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    while pos + 4 <= min(end, len(body)):
        etype, elen = struct.unpack("!HH", body[pos:pos + 4])
        exts[etype] = body[pos + 4:pos + 4 + elen]
        pos += 4 + elen
    return exts


def tls_info(c2s: bytes, s2c: bytes) -> dict:
    """Извлекает параметры TLS из открытой части рукопожатия.

    Возвращает словарь: версия, набор шифров, имя сервера (SNI),
    число и объём зашифрованных записей прикладных данных.
    """
    info: dict = {"app_records": 0, "app_bytes": 0}
    for data, side in ((c2s, "c"), (s2c, "s")):
        pos = 0
        while pos + 5 <= len(data):
            ctype, _ver, length = struct.unpack("!BHH", data[pos:pos + 5])
            rec = data[pos + 5:pos + 5 + length]
            pos += 5 + length
            if ctype == 23:
                info["app_records"] += 1
                info["app_bytes"] += length
            elif ctype == 22 and rec:
                hs_type = rec[0]
                body = rec[4:]
                if hs_type == 1 and side == "c" and len(body) > 38:      # ClientHello
                    p = 34
                    p += 1 + body[p]                                      # session_id
                    p += 2 + struct.unpack("!H", body[p:p + 2])[0]        # cipher_suites
                    p += 1 + body[p]                                      # compression
                    sni = _extensions(body, p).get(0)
                    if sni and len(sni) > 5:
                        info["sni"] = sni[5:].decode(errors="replace")
                elif hs_type == 2 and side == "s" and len(body) > 38:    # ServerHello
                    ver = struct.unpack("!H", body[:2])[0]
                    p = 34
                    p += 1 + body[p]
                    suite = struct.unpack("!H", body[p:p + 2])[0]
                    exts = _extensions(body, p + 3)
                    if 0x002B in exts:
                        ver = struct.unpack("!H", exts[0x002B][:2])[0]
                    info["version"] = TLS_VERSIONS.get(ver, hex(ver))
                    info["cipher"] = CIPHER_SUITES.get(suite, f"0x{suite:04x}")
            elif ctype not in (20, 21, 22, 23):
                break
    return info


def apply_tls(report: StreamReport, c2s: bytes, s2c: bytes, how: str) -> None:
    """Заполняет сведения о шифровании и добавляет справочную находку."""
    info = tls_info(c2s, s2c)
    report.tls = info
    report.encryption = f"{how}: {info.get('version', 'TLS')}, {info.get('cipher', '?')}"
    report.messages["TLS application_data"] += info["app_records"]
    report.add(INFO, "Данные прикладного протокола зашифрованы TLS",
               f"{info.get('version', '?')}, {info.get('cipher', '?')}, SNI={info.get('sni', '-')}, "
               f"зашифрованных записей: {info['app_records']} ({info['app_bytes']} байт)")


# ==========================================================================
# HTTP (WebDAV, WinRM, PSRP)
# ==========================================================================

def parse_http(data: bytes) -> list[tuple[str, dict[str, str], bytes]]:
    """Делит поток HTTP/1.1 на сообщения (стартовая строка, заголовки, тело).

    Поддерживаются тела с Content-Length и с передачей частями (chunked).
    """
    out, pos = [], 0
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            break
        head = data[pos:end].decode("iso-8859-1").split("\r\n")
        start, headers = head[0], {}
        for line in head[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        pos = end + 4
        body = b""
        if headers.get("transfer-encoding", "").lower() == "chunked":
            while True:
                eol = data.find(b"\r\n", pos)
                size = int(data[pos:eol].split(b";")[0] or b"0", 16)
                pos = eol + 2
                if size == 0:
                    pos = data.find(b"\r\n", pos) + 2
                    break
                body += data[pos:pos + size]
                pos += size + 2
        else:
            n = int(headers.get("content-length", "0") or 0)
            body = data[pos:pos + n]
            pos += n
        out.append((start, headers, body))
    return out


def _xml_tag(xml: str, local: str) -> list[str]:
    """Возвращает тексты всех элементов с локальным именем local (любой префикс)."""
    return re.findall(rf"<(?:[\w-]+:)?{local}(?:\s[^>]*)?>([^<]*)</(?:[\w-]+:)?{local}>", xml)


def _psrp_from_xml(report: StreamReport, xml: str) -> None:
    """Находит и декодирует сообщения PSRP в элементах creationXml, Arguments и Stream."""
    for b64 in _xml_tag(xml, "creationXml") + _xml_tag(xml, "Arguments") + _xml_tag(xml, "Stream"):
        try:
            msgs = psrp.decode_blob(b64)
        except (ValueError, struct.error):
            continue
        for m in msgs:
            report.messages[f"PSRP {m.type_name}"] += 1
            if m.message_type == psrp.CREATE_PIPELINE:
                cmd = re.findall(r'<S N="Cmd">([^<]*)</S>', m.data)
                report.add(HIGH, "Команда PowerShell передана в открытом виде (PSRP CREATE_PIPELINE)",
                           "; ".join(cmd))
            elif m.message_type == psrp.PIPELINE_OUTPUT:
                report.add(HIGH, "Результат выполнения команды PowerShell виден в трафике",
                           preview("; ".join(psrp.clixml_strings(m.data))))


def inspect_http(stream: Stream, report: StreamReport) -> None:
    """Анализ HTTP: WebDAV, WinRM (WS-Management), WMI поверх WinRM и PSRP."""
    if is_tls(stream.c2s):
        report.protocol += " (HTTPS)"
        apply_tls(report, stream.c2s, stream.s2c, "TLS с момента подключения")
        return
    requests, responses = parse_http(stream.c2s), parse_http(stream.s2c)
    is_winrm = any("/wsman" in r[0] for r in requests)
    report.protocol = "WinRM / WS-Management" if is_winrm else "WebDAV (HTTP)"
    for start, headers, body in requests:
        method, _, rest = start.partition(" ")
        url = rest.rsplit(" ", 1)[0]
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                creds = base64.b64decode(auth[6:]).decode("utf-8", "replace")
            except ValueError:
                creds = "?"
            report.add(HIGH, "Учётные данные Basic-аутентификации (Base64 – не шифрование)",
                       f"{auth[:40]}… → {creds}")
        elif auth.lower().startswith(("negotiate ", "ntlm ", "kerberos ")):
            report.add(INFO, "Аутентификация Negotiate/NTLM/Kerberos", auth.split()[0])
        xml = body.decode("utf-8", "replace")
        if is_winrm:
            actions = _xml_tag(xml, "Action")
            name = actions[0].rsplit("/", 1)[-1] if actions else ("Identify" if "Identify" in xml else "?")
            report.messages[f"WS-Man {name}"] += 1
            for res in _xml_tag(xml, "ResourceURI"):
                if "/wmi/" in res:
                    report.add(MEDIUM, "Запрос WMI через WinRM (класс CIM виден открыто)", res)
            _psrp_from_xml(report, xml)
        else:
            report.messages[f"{method}"] += 1
            if method == "PUT" and body:
                report.add(HIGH, "Содержимое загружаемого файла передано в открытом виде",
                           f"{url}: {preview(body)}")
            if method == "LOCK":
                owner = _xml_tag(xml, "href")
                if owner:
                    report.add(MEDIUM, "Владелец блокировки WebDAV (имя пользователя)", owner[0])
    for start, headers, body in responses:
        code = start.split(" ")[1] if " " in start else "?"
        xml = body.decode("utf-8", "replace")
        if is_winrm:
            items = re.findall(r"<p:(\w+)>([^<]*)</p:\1>", xml)
            if items:
                report.add(MEDIUM, "Сведения WMI об операционной системе сервера",
                           preview(", ".join(f"{k}={v}" for k, v in items)))
            version = _xml_tag(xml, "ProductVersion")
            if version:
                report.add(INFO, "Версия стека WinRM сервера (ответ Identify)", version[0])
            _psrp_from_xml(report, xml)
        else:
            report.messages[f"HTTP {code}"] += 1
            if code == "207":
                hrefs = _xml_tag(xml, "href")
                report.add(MEDIUM, "Структура каталогов сервера (ответ PROPFIND 207 Multi-Status)",
                           ", ".join(hrefs))
            if headers.get("content-type", "").startswith("application/octet-stream") and body:
                report.add(HIGH, "Содержимое скачиваемого файла передано в открытом виде", preview(body))
        server = headers.get("server")
        if server:
            report.add(INFO, "Заголовок Server раскрывает реализацию сервера", server)


# ==========================================================================
# LDAP
# ==========================================================================

def ldap_filter(f: ber.Tlv) -> str:
    """Преобразует фильтр поиска LDAP в строковую форму RFC 4515."""
    t = f.tag
    if t in (0, 1):
        return "(" + ("&" if t == 0 else "|") + "".join(ldap_filter(c) for c in f.children) + ")"
    if t == 2:
        return "(!" + ldap_filter(f.children[0]) + ")"
    if t in (3, 5, 6, 8):
        op = {3: "=", 5: ">=", 6: "<=", 8: "~="}[t]
        return f"({f.children[0].as_str()}{op}{f.children[1].as_str()})"
    if t == 4:
        parts = {c.tag: c.as_str() for c in f.children[1].children}
        return f"({f.children[0].as_str()}={parts.get(0, '')}*{parts.get(1, '')}{'*' if 1 in parts else ''}{parts.get(2, '')})"
    if t == 7:
        return f"({f.as_str()}=*)"
    return "(?)"


def _ldap_messages(data: bytes) -> tuple[list[ber.Tlv], int]:
    """Разбирает сообщения LDAP; возвращает их и позицию, где разбор остановился."""
    msgs, pos = [], 0
    while pos < len(data):
        try:
            msg, end = ber.decode(data, pos)
        except ber.BerError:
            break
        if msg.tag != ber.SEQUENCE or len(msg.children) < 2 or msg.children[1].cls != ber.APPLICATION:
            break
        msgs.append(msg)
        pos = end
    return msgs, pos


def inspect_ldap(stream: Stream, report: StreamReport) -> None:
    """Анализ LDAP: привязка, поиск, результаты, переход на TLS (StartTLS)."""
    if is_tls(stream.c2s):
        apply_tls(report, stream.c2s, stream.s2c, "LDAPS (TLS с момента подключения)")
        return
    c_msgs, c_end = _ldap_messages(stream.c2s)
    s_msgs, s_end = _ldap_messages(stream.s2c)
    for msg in c_msgs + s_msgs:
        op = msg.children[1]
        report.messages[LDAP_OPS.get(op.tag, f"op{op.tag}")] += 1
        if op.tag == 0:                                      # bindRequest
            dn, auth = op.children[1].as_str(), op.children[2]
            if auth.tag == 0:
                report.add(HIGH, "Простая привязка LDAP (simple bind): пароль открытым текстом",
                           f"DN={dn}, пароль={auth.value.decode('utf-8', 'replace')}")
            elif auth.tag == 3:
                mech = auth.children[0].as_str() if auth.children else "?"
                report.add(INFO, "Привязка SASL", mech)
        elif op.tag == 3:                                    # searchRequest
            report.add(MEDIUM, "Поисковый запрос к каталогу виден открыто",
                       f"base={op.children[0].as_str()}, filter={ldap_filter(op.children[6])}, "
                       f"attrs={[c.as_str() for c in op.children[7].children]}")
        elif op.tag == 4:                                    # searchResEntry
            attrs = {a.children[0].as_str(): [v.as_str() for v in a.children[1].children]
                     for a in op.children[1].children}
            report.add(MEDIUM, "Запись каталога Active Directory в ответе", preview(
                op.children[0].as_str() + " " + "; ".join(f"{k}={','.join(v)}" for k, v in attrs.items()), 160))
        elif op.tag == 23 and op.children and op.children[0].as_str() == STARTTLS_OID:
            report.add(INFO, "Запрошен переход на TLS (расширенная операция StartTLS)", STARTTLS_OID)
    if c_end < len(stream.c2s) and is_tls(stream.c2s[c_end:]):
        apply_tls(report, stream.c2s[c_end:], stream.s2c[s_end:], "StartTLS")


# ==========================================================================
# SMB2
# ==========================================================================

SMB2_COMMANDS = ["NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT", "TREE_DISCONNECT",
                 "CREATE", "CLOSE", "FLUSH", "READ", "WRITE", "LOCK", "IOCTL", "CANCEL", "ECHO",
                 "QUERY_DIRECTORY", "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"]
SMB2_DIALECTS = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2",
                 0x0311: "SMB 3.1.1", 0x02FF: "SMB2 wildcard"}


def _ntlm_field(blob: bytes, off: int) -> bytes:
    """Читает поле NTLMSSP (длина, макс. длина, смещение) по смещению off."""
    length, _maxlen, offset = struct.unpack("<HHI", blob[off:off + 8])
    return blob[offset:offset + length]


def inspect_ntlm(report: StreamReport, data: bytes) -> None:
    """Ищет сообщения NTLMSSP и раскрываемые ими сведения."""
    for m in re.finditer(rb"NTLMSSP\x00", data):
        blob = data[m.start():]
        if len(blob) < 12:
            continue
        mtype = struct.unpack("<I", blob[8:12])[0]
        report.messages[f"NTLMSSP type {mtype}"] += 1
        if mtype == 2 and len(blob) >= 32:
            target = _ntlm_field(blob, 12).decode("utf-16-le", "replace")
            report.add(INFO, "NTLM CHALLENGE: имя домена/сервера и серверный вызов (challenge)",
                       f"target={target}, challenge={blob[24:32].hex()}")
        elif mtype == 3 and len(blob) >= 52:
            user = _ntlm_field(blob, 36).decode("utf-16-le", "replace")
            dom = _ntlm_field(blob, 28).decode("utf-16-le", "replace")
            ws = _ntlm_field(blob, 44).decode("utf-16-le", "replace")
            nt = _ntlm_field(blob, 20)
            report.add(MEDIUM, "NTLM AUTHENTICATE: имя пользователя, домен и рабочая станция",
                       f"{dom}\\{user} с {ws}")
            if len(nt) > 24:
                report.add(HIGH, "Перехвачен ответ NTLMv2 (пригоден для подбора пароля офлайн)",
                           f"NTProofStr={nt[:16].hex()}…, длина ответа {len(nt)} байт")


def inspect_smb(stream: Stream, report: StreamReport) -> None:
    """Анализ SMB2/SMB3: диалект, подпись, шифрование, имена ресурсов и данные файлов."""
    signed = encrypted = False
    for data in (stream.c2s, stream.s2c):
        pos = 0
        while pos + 4 <= len(data):
            length = int.from_bytes(data[pos + 1:pos + 4], "big")
            pdu = data[pos + 4:pos + 4 + length]
            pos += 4 + length
            if pdu[:4] == b"\xffSMB":
                report.messages["SMB1 " + ("NEGOTIATE" if pdu[4] == 0x72 else hex(pdu[4]))] += 1
                continue
            if pdu[:4] == b"\xfdSMB":
                encrypted = True
                report.messages["SMB3 TRANSFORM (зашифровано)"] += 1
                continue
            off = 0
            while off + 64 <= len(pdu) and pdu[off:off + 4] == b"\xfeSMB":
                hdr = pdu[off:off + 64]
                cmd, flags, nxt = struct.unpack("<H", hdr[12:14])[0], struct.unpack("<I", hdr[16:20])[0], \
                    struct.unpack("<I", hdr[20:24])[0]
                msg = pdu[off:off + nxt] if nxt else pdu[off:]
                body = msg[64:]
                is_resp = bool(flags & 1)
                name = SMB2_COMMANDS[cmd] if cmd < len(SMB2_COMMANDS) else hex(cmd)
                report.messages[f"SMB2 {name} {'Response' if is_resp else 'Request'}"] += 1
                if flags & 0x08:
                    signed = True
                if cmd == 0 and is_resp and len(body) >= 6:
                    dialect = struct.unpack("<H", body[4:6])[0]
                    report.add(INFO, "Согласованный диалект SMB", SMB2_DIALECTS.get(dialect, hex(dialect)))
                elif cmd == 1:
                    inspect_ntlm(report, body)
                elif cmd == 3 and not is_resp and len(body) >= 8:
                    p_off, p_len = struct.unpack("<HH", body[4:8])
                    path = msg[p_off:p_off + p_len].decode("utf-16-le", "replace")
                    report.add(MEDIUM, "Путь к общему ресурсу (TREE_CONNECT)", path)
                elif cmd == 5 and not is_resp and len(body) >= 48:
                    n_off, n_len = struct.unpack("<HH", body[44:48])
                    fname = msg[n_off:n_off + n_len].decode("utf-16-le", "replace")
                    if fname:
                        report.add(MEDIUM, "Имя открываемого файла или канала (CREATE)", fname)
                elif cmd in (8, 9) and (is_resp if cmd == 8 else not is_resp) and len(body) >= 8:
                    if cmd == 9:
                        d_off, d_len = struct.unpack("<HI", body[2:8])
                    else:
                        d_off, d_len = body[2], struct.unpack("<I", body[4:8])[0]
                    chunk = msg[d_off:d_off + d_len]
                    if chunk[:2] == b"\x05\x00":
                        # DCE/RPC через именованный канал (например, \srvsvc при перечислении ресурсов).
                        report.messages["DCE/RPC через именованный канал"] += 1
                    elif chunk:
                        op = "Записываемые в файл" if cmd == 9 else "Прочитанные из файла"
                        report.add(HIGH, f"{op} данные переданы в открытом виде ({SMB2_COMMANDS[cmd]})",
                                   preview(chunk))
                if not nxt:
                    break
                off += nxt
    if encrypted:
        report.encryption = "шифрование SMB 3.x (AES-CCM/GCM)"
    else:
        report.encryption = "нет" + (" (подпись SMB включена)" if signed else ", подпись SMB не используется")
        report.add(MEDIUM if not signed else INFO,
                   "Шифрование SMB не применяется" + ("" if signed else "; сообщения не подписаны"), "")


# ==========================================================================
# RDP
# ==========================================================================

RDP_PROTOCOLS = {0: "Standard RDP Security", 1: "TLS", 2: "CredSSP (NLA)", 4: "RDSTLS", 8: "CredSSP EX"}


def _rdp_flags(value: int) -> str:
    """Расшифровывает битовую маску протоколов безопасности RDP."""
    if value == 0:
        return RDP_PROTOCOLS[0]
    return " | ".join(n for b, n in RDP_PROTOCOLS.items() if b and value & b)


def inspect_rdp(stream: Stream, report: StreamReport) -> None:
    """Анализ RDP: X.224 Connection Request/Confirm и переход на TLS."""
    c, s = stream.c2s, stream.s2c
    if len(c) < 11 or c[0] != 3:
        return
    c_len = struct.unpack("!H", c[2:4])[0]
    cr = c[4:c_len]
    report.messages["X.224 Connection Request"] += 1
    cookie = re.search(rb"Cookie: mstshash=([^\r]*)\r\n", cr)
    if cookie:
        report.add(MEDIUM, "Имя пользователя в поле Cookie (mstshash) передаётся открыто",
                   cookie.group(1).decode(errors="replace"))
    if cr[-8:-7] == b"\x01":
        req = struct.unpack("<I", cr[-4:])[0]
        report.add(INFO, "Клиент предлагает протоколы безопасности (RDP_NEG_REQ)", _rdp_flags(req))
    if len(s) >= 11 and s[0] == 3:
        s_len = struct.unpack("!H", s[2:4])[0]
        cc = s[4:s_len]
        report.messages["X.224 Connection Confirm"] += 1
        if cc[-8:-7] == b"\x02":
            sel = struct.unpack("<I", cc[-4:])[0]
            report.add(INFO if sel else HIGH, "Сервер выбрал протокол безопасности (RDP_NEG_RSP)",
                       _rdp_flags(sel))
            if sel and is_tls(c[c_len:]):
                apply_tls(report, c[c_len:], s[s_len:], "Enhanced RDP Security")
            elif sel == 0:
                report.encryption = "Standard RDP Security (RC4) – устаревшая"


# ==========================================================================
# DCE/RPC (WMI через DCOM)
# ==========================================================================

RPC_PTYPES = {0: "request", 2: "response", 3: "fault", 11: "bind", 12: "bind_ack", 13: "bind_nak",
              14: "alter_context", 15: "alter_context_resp", 16: "auth3"}
RPC_INTERFACES = {
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPM (Endpoint Mapper)",
    "99fcfec4-5260-101b-bbcb-00aa0021347a": "IObjectExporter (DCOM OXID Resolver)",
    "000001a0-0000-0000-c000-000000000046": "IRemoteSCMActivator (DCOM)",
    "f309ad18-d86a-11d0-a075-00c04fb68820": "IWbemLevel1Login (WMI)",
    "9556dc99-828c-11cf-a37e-00aa003240c7": "IWbemServices (WMI)",
    "86d35949-83c9-4044-b424-db363231fd0c": "ITaskSchedulerService (MS-TSCH)",
    "367abb81-9844-35f1-ad32-98f038001003": "SVCCTL (MS-SCMR)",
}
AUTH_LEVELS = {1: "NONE", 2: "CONNECT", 3: "CALL", 4: "PKT", 5: "PKT_INTEGRITY", 6: "PKT_PRIVACY"}


def inspect_rpc(stream: Stream, report: StreamReport) -> None:
    """Анализ DCE/RPC: интерфейсы, номера операций, уровень аутентификации, строки в ответах."""
    auth_seen = set()
    for data, side in ((stream.c2s, "c"), (stream.s2c, "s")):
        pos = 0
        while pos + 16 <= len(data) and data[pos] == 5:
            ptype = data[pos + 2]
            frag_len, auth_len = struct.unpack("<HH", data[pos + 8:pos + 12])
            pdu = data[pos:pos + frag_len]
            pos += frag_len
            name = RPC_PTYPES.get(ptype, str(ptype))
            report.messages[f"DCE/RPC {name}"] += 1
            if auth_len and len(pdu) >= frag_len:
                auth_seen.add(pdu[frag_len - auth_len - 8 + 1])
            if ptype in (11, 14) and len(pdu) >= 48:
                iface = str(uuid.UUID(bytes_le=pdu[32:48]))
                report.add(INFO, "Привязка к интерфейсу RPC", RPC_INTERFACES.get(iface, iface))
            elif ptype == 0 and len(pdu) >= 24:
                report.messages[f"opnum {struct.unpack('<H', pdu[22:24])[0]}"] += 1
            elif ptype == 2 and side == "s":
                strings = [s.decode("utf-16-le") for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", pdu[24:])]
                if strings:
                    report.add(MEDIUM, "Ответ RPC без аутентификации раскрывает сетевые имена и адреса",
                               preview(", ".join(strings), 160))
    if auth_seen:
        lvl = max(auth_seen)
        report.encryption = "шифрование RPC (PKT_PRIVACY)" if lvl == 6 else f"нет (уровень {AUTH_LEVELS.get(lvl)})"
    else:
        report.encryption = "нет (вызовы без аутентификации)"
        report.add(MEDIUM, "Вызовы RPC выполнены без аутентификации и шифрования", "")
