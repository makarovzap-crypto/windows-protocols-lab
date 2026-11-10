"""Запись и чтение файлов захвата сетевого трафика.

Модуль реализует без внешних зависимостей:
  * запись файла в классическом формате pcap (libpcap) с канальным уровнем
    Ethernet, который открывается в Wireshark и tshark;
  * построение кадров Ethernet/IPv4/TCP с корректными контрольными суммами;
  * моделирование TCP-соединения (тройное рукопожатие, передача данных
    сегментами не более MSS, подтверждения и завершение соединения);
  * чтение файлов pcap и pcapng (в том числе сохранённых Wireshark)
    и разбор сегментов TCP поверх IPv4 и IPv6.
"""

from __future__ import annotations

import ipaddress
import random
import struct
import threading
import time
from dataclasses import dataclass

# Флаги заголовка TCP.
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# Типы канального уровня (LINKTYPE_*), поддерживаемые при чтении.
LINKTYPE_NULL = 0          # петлевой интерфейс BSD/Npcap Loopback
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101         # «сырой» IP без канального заголовка
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def checksum(data: bytes) -> int:
    """Вычисляет 16-битную контрольную сумму Интернета (RFC 1071).

    Аргументы:
        data: байты, по которым считается сумма.
    Возвращает:
        Дополнение до единицы суммы 16-битных слов.
    """
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_frame(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
                sport: int, dport: int, seq: int, ack: int, flags: int,
                payload: bytes = b"", ip_id: int = 0) -> bytes:
    """Формирует кадр Ethernet II с пакетом IPv4 и сегментом TCP.

    Аргументы:
        src_mac, dst_mac: MAC-адреса отправителя и получателя (6 байт);
        src_ip, dst_ip: IPv4-адреса в точечной нотации;
        sport, dport: TCP-порты отправителя и получателя;
        seq, ack: порядковый номер и номер подтверждения;
        flags: битовая маска флагов TCP (SYN, ACK, PSH, FIN, RST);
        payload: полезная нагрузка сегмента;
        ip_id: идентификатор IP-пакета.
    Возвращает:
        Готовый кадр в виде байтов.
    """
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, 64240, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp_sum = checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload),
                     ip_id & 0xFFFF, 0x4000, 128, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = dst_mac + src_mac + b"\x08\x00"
    return eth + ip + tcp + payload


class PcapWriter:
    """Потокобезопасная запись кадров в файл формата pcap."""

    def __init__(self, path: str):
        """Создаёт файл и записывает глобальный заголовок pcap.

        Аргументы:
            path: путь к создаваемому файлу захвата.
        """
        self._file = open(path, "wb")
        self._lock = threading.Lock()
        self._ip_id = random.randint(1, 30000)
        # magic, версия 2.4, часовой пояс, точность, snaplen, тип канала.
        self._file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144,
                                     LINKTYPE_ETHERNET))

    def next_ip_id(self) -> int:
        """Возвращает очередной идентификатор IP-пакета."""
        with self._lock:
            self._ip_id += 1
            return self._ip_id

    def write(self, frame: bytes, ts: float | None = None) -> None:
        """Записывает один кадр с отметкой времени.

        Аргументы:
            frame: байты кадра Ethernet;
            ts: время в секундах Unix (по умолчанию текущее).
        """
        ts = time.time() if ts is None else ts
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        with self._lock:
            self._file.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            self._file.write(frame)
            self._file.flush()

    def close(self) -> None:
        """Закрывает файл захвата."""
        with self._lock:
            self._file.close()


class TcpSession:
    """Модель TCP-соединения, кадры которого записываются в pcap.

    Класс отслеживает порядковые номера обеих сторон, поэтому Wireshark
    корректно собирает потоки (Follow TCP Stream) и находит границы
    сообщений прикладных протоколов.
    """

    MSS = 1460

    def __init__(self, writer: PcapWriter, client: tuple[str, int], server: tuple[str, int],
                 client_mac: bytes, server_mac: bytes):
        """Записывает тройное рукопожатие TCP.

        Аргументы:
            writer: объект записи pcap;
            client, server: пары (IP-адрес, порт) клиента и сервера;
            client_mac, server_mac: MAC-адреса сторон.
        """
        self._w = writer
        self._ends = {"c": (client, client_mac), "s": (server, server_mac)}
        self._seq = {"c": random.randint(1, 2**31), "s": random.randint(1, 2**31)}
        self._lock = threading.Lock()
        self._closed = False
        self._emit("c", SYN)
        self._seq["c"] += 1
        self._emit("s", SYN | ACK)
        self._seq["s"] += 1
        self._emit("c", ACK)

    def _emit(self, side: str, flags: int, payload: bytes = b"") -> None:
        """Записывает один сегмент от стороны side ('c' или 's')."""
        other = "s" if side == "c" else "c"
        (src_ip, sport), src_mac = self._ends[side]
        (dst_ip, dport), dst_mac = self._ends[other]
        ack = self._seq[other] if flags & ACK else 0
        frame = build_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport,
                            self._seq[side], ack, flags, payload, self._w.next_ip_id())
        self._w.write(frame)

    def send(self, side: str, data: bytes) -> None:
        """Записывает передачу данных от стороны side и подтверждение получателя.

        Аргументы:
            side: 'c' – данные клиента, 's' – данные сервера;
            data: передаваемые байты (делятся на сегменты не более MSS).
        """
        with self._lock:
            if self._closed or not data:
                return
            for i in range(0, len(data), self.MSS):
                chunk = data[i:i + self.MSS]
                self._emit(side, PSH | ACK, chunk)
                self._seq[side] += len(chunk)
            self._emit("s" if side == "c" else "c", ACK)

    def close(self, side: str = "c") -> None:
        """Записывает корректное завершение соединения (FIN/ACK с обеих сторон)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            other = "s" if side == "c" else "c"
            self._emit(side, FIN | ACK)
            self._seq[side] += 1
            self._emit(other, FIN | ACK)
            self._seq[other] += 1
            self._emit(side, ACK)


# --------------------------------------------------------------------------
# Чтение файлов захвата
# --------------------------------------------------------------------------

@dataclass
class TcpSegment:
    """Сегмент TCP, извлечённый из файла захвата."""

    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    flags: int
    payload: bytes


def _iter_pcap_records(data: bytes):
    """Перебирает записи файла pcap или pcapng.

    Возвращает (генератор) кортежи (время, тип канала, байты кадра).
    """
    if len(data) < 24:
        return
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
        return
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Неизвестный формат файла захвата")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        frame = data[pos:pos + incl]
        pos += incl
        yield sec + frac / (1e9 if nano else 1e6), linktype, frame


def _iter_pcapng(data: bytes):
    """Перебирает пакеты файла pcapng (блоки SHB, IDB, EPB, SPB)."""
    pos = 0
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    while pos + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if btype == 0x0A0D0D0A:
            bom = data[pos + 8:pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if blen < 12:
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            resol = 1e-6
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[opt:opt + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = body[opt + 4]
                    resol = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
                opt += 4 + olen + (-olen % 4)
            interfaces.append((linktype, resol))
        elif btype == 6 and interfaces:  # Enhanced Packet Block
            if_id, hi, lo, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
            linktype, resol = interfaces[if_id]
            yield ((hi << 32) | lo) * resol, linktype, body[20:20 + caplen]
        elif btype == 3 and interfaces:  # Simple Packet Block
            linktype, _ = interfaces[0]
            yield 0.0, linktype, body[4:]
        pos += blen


def _ip_from_link(linktype: int, frame: bytes) -> bytes | None:
    """Отделяет IP-пакет от заголовка канального уровня."""
    if linktype == LINKTYPE_ETHERNET:
        off, etype = 14, struct.unpack("!H", frame[12:14])[0]
        while etype == 0x8100 and len(frame) >= off + 4:  # VLAN 802.1Q
            etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if etype in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_NULL:
        return frame[4:]
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_LINUX_SLL:
        return frame[16:]
    if linktype == LINKTYPE_LINUX_SLL2:
        return frame[20:]
    return None


def parse_tcp(ts: float, ip: bytes) -> TcpSegment | None:
    """Разбирает IPv4/IPv6-пакет и возвращает сегмент TCP либо None."""
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4:
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        if ip[9] != 6:
            return None
        src, dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        tcp = ip[ihl:total if total else None]
    elif version == 6:
        if ip[6] != 6:
            return None
        plen = struct.unpack("!H", ip[4:6])[0]
        src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
        tcp = ip[40:40 + plen]
    else:
        return None
    if len(tcp) < 20:
        return None
    sport, dport, seq, _ack, off, flags = struct.unpack("!HHIIBB", tcp[:14])
    return TcpSegment(ts, src, sport, dst, dport, seq, flags, tcp[(off >> 4) * 4:])


def read_tcp_segments(path: str) -> list[TcpSegment]:
    """Читает файл захвата и возвращает список сегментов TCP.

    Аргументы:
        path: путь к файлу .pcap или .pcapng.
    Возвращает:
        Список сегментов в порядке их следования в файле.
    """
    with open(path, "rb") as f:
        data = f.read()
    segments = []
    for ts, linktype, frame in _iter_pcap_records(data):
        ip = _ip_from_link(linktype, frame)
        seg = parse_tcp(ts, ip) if ip else None
        if seg:
            segments.append(seg)
    return segments
