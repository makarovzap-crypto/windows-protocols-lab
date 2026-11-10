"""Анализатор файлов захвата: определение протоколов и поиск открытых данных.

Анализатор работает как с файлами, записанными стендом, так и с файлами
.pcap/.pcapng, сохранёнными в Wireshark при захвате реального трафика.
"""

from __future__ import annotations

import json

from ..pcap import read_tcp_segments
from . import inspectors
from .model import HIGH, INFO, MEDIUM, StreamReport
from .streams import Stream, build_streams

# Порт сервера -> (название протокола, функция анализа).
PORT_MAP = {
    445: ("SMB", inspectors.inspect_smb), 139: ("SMB (NetBIOS)", inspectors.inspect_smb),
    80: ("HTTP", inspectors.inspect_http), 443: ("HTTP", inspectors.inspect_http),
    5985: ("WinRM", inspectors.inspect_http), 5986: ("WinRM", inspectors.inspect_http),
    389: ("LDAP", inspectors.inspect_ldap), 636: ("LDAP", inspectors.inspect_ldap),
    3268: ("LDAP (Global Catalog)", inspectors.inspect_ldap),
    3269: ("LDAP (Global Catalog)", inspectors.inspect_ldap),
    3389: ("RDP", inspectors.inspect_rdp), 135: ("DCE/RPC (WMI/DCOM)", inspectors.inspect_rpc),
}

# Фильтры отображения Wireshark для протоколов стенда.
WIRESHARK_FILTERS = {
    "SMB": "smb2 || smb || ntlmssp",
    "WebDAV": 'http.request.method in {"PROPFIND", "MKCOL", "PUT", "LOCK", "DELETE"} || http.response.code == 207',
    "LDAP": "ldap || tcp.port == 636",
    "RDP": "tpkt || rdp || tcp.port == 3389",
    "WinRM / PSRP": 'tcp.port in {5985, 5986} && (http || tls)',
    "WMI (DCOM/RPC)": "dcerpc || epm || dcom",
    "Учётные данные": 'http.authorization || ldap.simple || ntlmssp.messagetype == 3',
    "TLS": "tls.handshake",
}


def _guess(stream: Stream):
    """Определяет протокол по порту сервера, а при неизвестном порте – по содержимому."""
    if stream.server_port in PORT_MAP:
        return PORT_MAP[stream.server_port]
    head = stream.c2s[:8]
    if head[:1] == b"\x05":
        return "DCE/RPC", inspectors.inspect_rpc
    if head[4:8] in (b"\xfeSMB", b"\xffSMB"):
        return "SMB", inspectors.inspect_smb
    if head[:1] == b"\x30":
        return "LDAP", inspectors.inspect_ldap
    if head.split(b" ")[0] in (b"GET", b"POST", b"PUT", b"OPTIONS", b"PROPFIND"):
        return "HTTP", inspectors.inspect_http
    return None, None


def analyze(path: str) -> list[StreamReport]:
    """Анализирует файл захвата.

    Аргументы:
        path: путь к файлу .pcap или .pcapng.
    Возвращает:
        Отчёты по TCP-потокам, содержащим данные прикладных протоколов.
    """
    reports = []
    for st in build_streams(read_tcp_segments(path)):
        if not st.c2s and not st.s2c:
            continue
        proto, func = _guess(st)
        if func is None:
            continue
        rep = StreamReport(st.index, proto, f"{st.client[0]}:{st.client[1]}",
                           f"{st.server[0]}:{st.server[1]}", st.packets, len(st.c2s), len(st.s2c))
        try:
            func(st, rep)
        except Exception as exc:  # повреждённые данные не должны прерывать анализ
            rep.add(INFO, "Ошибка разбора потока", f"{exc.__class__.__name__}: {exc}")
        reports.append(rep)
    return reports


def to_json(reports: list[StreamReport]) -> str:
    """Сериализует результаты в JSON."""
    return json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2)


def to_markdown(reports: list[StreamReport], source: str) -> str:
    """Формирует отчёт в формате Markdown: сводная таблица и находки по потокам."""
    lines = [f"# Отчёт анализа трафика: {source}", "",
             "## Сводная таблица", "",
             "| Поток | Протокол | Сервер | Пакетов | Байт (К→С / С→К) | Защита канала | Высокий | Средний |",
             "|---|---|---|---|---|---|---|---|"]
    for r in reports:
        hi = sum(f.severity == HIGH for f in r.findings)
        me = sum(f.severity == MEDIUM for f in r.findings)
        lines.append(f"| {r.index} | {r.protocol} | {r.server} | {r.packets} | {r.bytes_c2s} / {r.bytes_s2c} "
                     f"| {r.encryption} | {hi} | {me} |")
    lines += ["", "## Находки по потокам", ""]
    for r in reports:
        lines.append(f"### Поток {r.index}: {r.protocol} ({r.client} → {r.server})")
        lines.append("")
        if r.messages:
            lines.append("Типы сообщений: " + ", ".join(f"{k} ×{v}" for k, v in r.messages.items()))
            lines.append("")
        for f in r.findings:
            ev = f" — `{f.evidence}`" if f.evidence else ""
            lines.append(f"- **[{f.severity}]** {f.title}{ev}")
        lines.append("")
    lines += ["## Фильтры отображения Wireshark", "", "| Назначение | Фильтр |", "|---|---|"]
    lines += [f"| {k} | `{v}` |" for k, v in WIRESHARK_FILTERS.items()]
    return "\n".join(lines) + "\n"


def to_console(reports: list[StreamReport]) -> str:
    """Формирует краткую сводку для вывода в консоль."""
    out = [f"{'Поток':>5}  {'Протокол':<28} {'Сервер':<22} {'Защита канала':<48} В  С"]
    for r in reports:
        hi = sum(f.severity == HIGH for f in r.findings)
        me = sum(f.severity == MEDIUM for f in r.findings)
        out.append(f"{r.index:>5}  {r.protocol[:28]:<28} {r.server:<22} {r.encryption[:48]:<48} {hi}  {me}")
    out.append("")
    for r in reports:
        for f in r.findings:
            if f.severity == HIGH:
                out.append(f"[{r.index}] {r.protocol}: {f.title}: {f.evidence}")
    return "\n".join(out)


__all__ = ["analyze", "to_json", "to_markdown", "to_console", "WIRESHARK_FILTERS", "HIGH", "MEDIUM", "INFO"]
