"""Сборка TCP-потоков из сегментов файла захвата.

Сегменты группируются по паре конечных точек, упорядочиваются по
относительному порядковому номеру (с учётом переполнения 32-битного
счётчика), повторные передачи отбрасываются. Результат – два непрерывных
потока байтов (клиент -> сервер и сервер -> клиент) и последовательность
порций данных в порядке их появления в захвате.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..pcap import SYN, ACK, TcpSegment

# Известные порты серверов (определяют, какая сторона соединения – сервер).
KNOWN_PORTS = {80, 135, 139, 389, 443, 445, 636, 3268, 3269, 3389, 5985, 5986}


@dataclass
class Stream:
    """Двунаправленный TCP-поток."""

    index: int
    client: tuple[str, int]
    server: tuple[str, int]
    c2s: bytes = b""
    s2c: bytes = b""
    packets: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    # Порции данных в порядке появления: ('c' | 's', байты).
    chunks: list[tuple[str, bytes]] = field(default_factory=list)

    @property
    def server_port(self) -> int:
        """Порт серверной стороны."""
        return self.server[1]


def _assemble(segments: list[TcpSegment], isn: int | None) -> tuple[bytes, list[tuple[int, bytes]]]:
    """Собирает однонаправленный поток из сегментов.

    Возвращает итоговые байты и список (порядковый номер в выборке, порция)
    для восстановления общего порядка обмена.
    """
    data_segs = [(i, s) for i, s in enumerate(segments) if s.payload]
    if not data_segs:
        return b"", []
    base = isn if isn is not None else min(s.seq for _, s in data_segs)
    out = bytearray()
    pieces: list[tuple[int, bytes]] = []
    for order, seg in sorted(data_segs, key=lambda x: ((x[1].seq - base) % 2**32, x[0])):
        rel = (seg.seq - base) % 2**32
        if rel + len(seg.payload) <= len(out):
            continue                       # повторная передача
        new = seg.payload[max(0, len(out) - rel):] if rel <= len(out) else seg.payload
        out += new
        pieces.append((order, new))
    return bytes(out), pieces


def build_streams(segments: list[TcpSegment]) -> list[Stream]:
    """Группирует сегменты в TCP-потоки.

    Аргументы:
        segments: сегменты в порядке следования в файле захвата.
    Возвращает:
        Список потоков в порядке их начала.
    """
    groups: dict[tuple, list[tuple[int, TcpSegment]]] = {}
    order: list[tuple] = []
    for i, seg in enumerate(segments):
        key = tuple(sorted([(seg.src, seg.sport), (seg.dst, seg.dport)]))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((i, seg))

    streams = []
    for idx, key in enumerate(order):
        items = groups[key]
        segs = [s for _, s in items]
        syn = next((s for s in segs if s.flags & SYN and not s.flags & ACK), None)
        if syn:
            client, server = (syn.src, syn.sport), (syn.dst, syn.dport)
        else:
            a, b = key
            client, server = (b, a) if a[1] in KNOWN_PORTS and b[1] not in KNOWN_PORTS else (a, b)
            if a[1] not in KNOWN_PORTS and b[1] not in KNOWN_PORTS and a[1] < b[1]:
                client, server = b, a
        st = Stream(idx, client, server, packets=len(segs), first_ts=segs[0].ts, last_ts=segs[-1].ts)
        c_segs = [(gi, s) for gi, s in items if (s.src, s.sport) == client]
        s_segs = [(gi, s) for gi, s in items if (s.src, s.sport) == server]

        def isn_of(lst):
            """Начальный порядковый номер (из сегмента SYN) + 1 либо None."""
            for _, s in lst:
                if s.flags & SYN:
                    return (s.seq + 1) % 2**32
            return None

        st.c2s, c_pieces = _assemble([s for _, s in c_segs], isn_of(c_segs))
        st.s2c, s_pieces = _assemble([s for _, s in s_segs], isn_of(s_segs))
        merged = [(c_segs[o][0], "c", d) for o, d in c_pieces] + [(s_segs[o][0], "s", d) for o, d in s_pieces]
        st.chunks = [(side, d) for _, side, d in sorted(merged, key=lambda x: x[0])]
        streams.append(st)
    return streams
