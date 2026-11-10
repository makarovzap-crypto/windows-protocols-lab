"""Точка входа стенда «Протоколы Windows в корпоративной сети».

Команды:
    python main.py run       – запустить стенд, записать трафик и проанализировать его;
    python main.py analyze F – проанализировать готовый файл захвата F (.pcap/.pcapng),
                               например сохранённый в Wireshark;
    python main.py list      – показать сценарии и порты;
    python main.py dump F --stream N – шестнадцатеричный дамп данных потока N.

Примеры:
    python main.py run
    python main.py run --only ldap ldaps winrm
    python main.py analyze capture.pcapng --out results
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from stand import analysis, config, runner


def _write_reports(pcap: str, out_dir: str) -> None:
    """Анализирует файл захвата и сохраняет отчёты report.md и report.json."""
    reports = analysis.analyze(pcap)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write(analysis.to_markdown(reports, os.path.basename(pcap)))
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        f.write(analysis.to_json(reports))
    print(analysis.to_console(reports))
    print(f"\nОтчёты: {os.path.join(out_dir, 'report.md')}, {os.path.join(out_dir, 'report.json')}")


def _dump(pcap: str, stream_index: int, limit: int) -> None:
    """Выводит полезную нагрузку сегментов TCP-потока в шестнадцатеричном виде.

    Формат аналогичен панели байтов Wireshark: смещение, 16 байт в
    шестнадцатеричной записи и их представление в ASCII.
    Аргументы:
        pcap: путь к файлу захвата;
        stream_index: номер потока (как tcp.stream в Wireshark);
        limit: максимальное число выводимых сегментов с данными.
    """
    from stand.analysis.streams import build_streams
    from stand.pcap import read_tcp_segments

    segments = read_tcp_segments(pcap)
    streams = build_streams(segments)
    st = streams[stream_index]
    ends = {st.client, st.server}
    shown = 0
    for no, seg in enumerate(segments, start=1):
        if not seg.payload or {(seg.src, seg.sport), (seg.dst, seg.dport)} != ends:
            continue
        print(f"Кадр {no}: {seg.src}:{seg.sport} → {seg.dst}:{seg.dport}, данных {len(seg.payload)} байт")
        for off in range(0, len(seg.payload), 16):
            chunk = seg.payload[off:off + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {off:04x}  {hexpart:<47}  {text}")
        print()
        shown += 1
        if shown >= limit:
            break


def main(argv: list[str] | None = None) -> int:
    """Разбирает аргументы командной строки и выполняет команду."""
    parser = argparse.ArgumentParser(description="Стенд исследования протоколов Windows с Wireshark")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="запустить сценарии и записать трафик")
    p_run.add_argument("--out", default="output", help="каталог результатов (по умолчанию output)")
    p_run.add_argument("--only", nargs="+", choices=runner.ALL_SCENARIOS, help="запустить только эти сценарии")
    p_run.add_argument("--no-keylog", action="store_true", help="не сохранять ключи TLS")
    p_run.add_argument("-v", "--verbose", action="store_true", help="подробный журнал")
    p_an = sub.add_parser("analyze", help="проанализировать файл .pcap/.pcapng")
    p_an.add_argument("pcap")
    p_an.add_argument("--out", default="output")
    sub.add_parser("list", help="показать сценарии и порты")
    p_dump = sub.add_parser("dump", help="шестнадцатеричный дамп данных TCP-потока")
    p_dump.add_argument("pcap")
    p_dump.add_argument("--stream", type=int, required=True, help="номер потока (tcp.stream)")
    p_dump.add_argument("--limit", type=int, default=4, help="число сегментов (по умолчанию 4)")
    args = parser.parse_args(argv)

    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")

    if args.cmd == "list":
        print(f"{'Сценарий':<15}{'Протокол':<22}{'Сервер':>8}{'Прокси':>8}{'В pcap':>8}  TLS")
        for name in runner.ALL_SCENARIOS:
            s = config.SERVICES[name]
            print(f"{name:<15}{s.protocol:<22}{s.real_port:>8}{s.proxy_port:>8}{s.virtual_port:>8}  "
                  f"{'да' if s.tls else 'нет'}")
        return 0
    if args.cmd == "dump":
        _dump(args.pcap, args.stream, args.limit)
        return 0
    if args.cmd == "analyze":
        _write_reports(args.pcap, args.out)
        return 0

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(name)s: %(message)s")
    logging.getLogger("stand").setLevel(logging.INFO)
    results = runner.run(args.out, args.only, keylog=not args.no_keylog)
    failed = [k for k, v in results.items() if not v.startswith("OK")]
    pcap = os.path.join(args.out, "windows_protocols.pcap")
    print(f"\nФайл захвата: {pcap}")
    if not args.no_keylog:
        print(f"Ключи TLS для Wireshark: {os.path.join(args.out, 'tls_keys.log')}")
    print()
    _write_reports(pcap, args.out)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
