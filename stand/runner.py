"""Запуск стенда: серверы, записывающие прокси и клиентские сценарии."""

from __future__ import annotations

import logging
import os
import tempfile
import time
from collections.abc import Callable

from . import config, scenarios, tls
from .pcap import PcapWriter
from .recorder import RecordingProxy
from .servers import http_common, ldap_server, rdp, smb, webdav, winrm

log = logging.getLogger("stand")

ALL_SCENARIOS = ["smb", "webdav", "webdav_tls", "ldap", "ldap_starttls", "ldaps",
                 "rdp", "winrm", "winrm_tls", "wmi_dcom"]


def _serve(server) -> None:
    """Запускает serve_forever() сервера socketserver в фоновом потоке."""
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()


def run(out_dir: str, selected: list[str] | None = None, keylog: bool = True) -> dict[str, str]:
    """Запускает выбранные сценарии и записывает трафик в pcap.

    Аргументы:
        out_dir: каталог для результатов (pcap, журнал ключей TLS, сертификаты);
        selected: имена сценариев (по умолчанию все);
        keylog: записывать ли сеансовые ключи TLS в файл tls_keys.log.
    Возвращает:
        Словарь «сценарий -> результат или текст ошибки».
    """
    if not selected:
        selected = list(ALL_SCENARIOS)
        if os.name != "nt":
            # Сценарий WMI/DCOM обращается к службе RPC Windows (порт 135) и вне Windows недоступен.
            selected.remove("wmi_dcom")
            log.info("wmi_dcom пропущен: требуется операционная система Windows")
    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "windows_protocols.pcap")
    keylog_path = os.path.join(out_dir, "tls_keys.log") if keylog else None
    if keylog_path and os.path.exists(keylog_path):
        os.remove(keylog_path)
    cert, key = tls.ensure_certificate(os.path.join(out_dir, "certs"))
    srv_ctx = tls.server_context(cert, key)
    cli_ctx = tls.client_context(keylog_path)

    S = config.SERVICES
    servers = []
    starters: dict[str, Callable[[], None]] = {
        "smb": lambda: smb.start(S["smb"].real_port, tempfile.mkdtemp(prefix="smb_share_")),
        "webdav": lambda: servers.append(http_common.make_server(S["webdav"].real_port,
                                                                 webdav.WebDavHandler, None)),
        "webdav_tls": lambda: servers.append(http_common.make_server(S["webdav_tls"].real_port,
                                                                     webdav.WebDavHandler, srv_ctx)),
        "ldap": lambda: servers.append(ldap_server.make_server(S["ldap"].real_port, None, False)),
        "ldap_starttls": lambda: servers.append(ldap_server.make_server(S["ldap_starttls"].real_port,
                                                                        srv_ctx, False)),
        "ldaps": lambda: servers.append(ldap_server.make_server(S["ldaps"].real_port, srv_ctx, True)),
        "rdp": lambda: servers.append(rdp.make_server(S["rdp"].real_port, srv_ctx)),
        "winrm": lambda: servers.append(http_common.make_server(S["winrm"].real_port,
                                                                winrm.WinRmHandler, None)),
        "winrm_tls": lambda: servers.append(http_common.make_server(S["winrm_tls"].real_port,
                                                                    winrm.WinRmHandler, srv_ctx)),
        "wmi_dcom": lambda: None,  # используется настоящая служба RPC хоста
    }
    actions: dict[str, Callable[[], str]] = {
        "smb": lambda: scenarios.smb_scenario(S["smb"]),
        "webdav": lambda: scenarios.webdav_scenario(S["webdav"], None),
        "webdav_tls": lambda: scenarios.webdav_scenario(S["webdav_tls"], cli_ctx),
        "ldap": lambda: scenarios.ldap_scenario(S["ldap"], None, "plain"),
        "ldap_starttls": lambda: scenarios.ldap_scenario(S["ldap_starttls"], cli_ctx, "starttls"),
        "ldaps": lambda: scenarios.ldap_scenario(S["ldaps"], cli_ctx, "ldaps"),
        "rdp": lambda: scenarios.rdp_scenario(S["rdp"], cli_ctx),
        "winrm": lambda: scenarios.winrm_scenario(S["winrm"], None),
        "winrm_tls": lambda: scenarios.winrm_scenario(S["winrm_tls"], cli_ctx),
        "wmi_dcom": lambda: scenarios.wmi_dcom_scenario(S["wmi_dcom"]),
    }

    writer = PcapWriter(pcap_path)
    proxies = []
    results: dict[str, str] = {}
    try:
        for name in selected:
            starters[name]()
            proxies.append(RecordingProxy(writer, S[name]).start())
        for srv in servers:
            _serve(srv)
        time.sleep(0.5)
        for name in selected:
            try:
                results[name] = "OK: " + actions[name]()
            except Exception as exc:  # сценарий не должен останавливать остальные
                log.exception("Сценарий %s завершился ошибкой", name)
                results[name] = f"ОШИБКА: {exc.__class__.__name__}: {exc}"
            time.sleep(0.3)  # даём прокси дописать завершение соединений
            log.info("%-14s %s", name, results[name])
    finally:
        time.sleep(0.5)
        for p in proxies:
            p.stop()
        for srv in servers:
            srv.shutdown()
            srv.server_close()
        writer.close()
    return results
