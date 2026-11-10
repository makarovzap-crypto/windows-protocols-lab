"""Кодирование и декодирование BER (Basic Encoding Rules, ITU-T X.690).

BER используется протоколом LDAP: каждое сообщение – это структура ASN.1,
закодированная в виде вложенных элементов «тег – длина – значение» (TLV).
Модуль содержит минимальный набор функций, достаточный для учебного
LDAP-сервера и анализатора трафика.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Классы тегов ASN.1.
UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

# Универсальные теги.
BOOLEAN, INTEGER, OCTET_STRING, ENUMERATED, SEQUENCE, SET = 0x01, 0x02, 0x04, 0x0A, 0x10, 0x11


class BerError(ValueError):
    """Ошибка разбора BER (неполные или повреждённые данные)."""


@dataclass
class Tlv:
    """Декодированный элемент BER.

    Атрибуты:
        cls: класс тега (UNIVERSAL, APPLICATION, CONTEXT, PRIVATE);
        constructed: признак составного элемента;
        tag: номер тега;
        value: байты значения;
        children: вложенные элементы (для составных элементов).
    """

    cls: int
    constructed: bool
    tag: int
    value: bytes
    children: list["Tlv"] = field(default_factory=list)

    def as_int(self) -> int:
        """Интерпретирует значение как целое со знаком (INTEGER, ENUMERATED)."""
        return int.from_bytes(self.value, "big", signed=True) if self.value else 0

    def as_str(self) -> str:
        """Интерпретирует значение как строку UTF-8 (OCTET STRING в LDAP)."""
        return self.value.decode("utf-8", errors="replace")


def read_header(data: bytes, pos: int = 0) -> tuple[int, bool, int, int, int]:
    """Читает тег и длину элемента.

    Возвращает кортеж (класс, составной, номер тега, длина значения,
    смещение начала значения). Генерирует BerError при нехватке данных.
    """
    if pos >= len(data):
        raise BerError("нет данных для тега")
    first = data[pos]
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    pos += 1
    if tag == 0x1F:  # длинная форма номера тега
        tag = 0
        while True:
            if pos >= len(data):
                raise BerError("обрыв номера тега")
            b = data[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if pos >= len(data):
        raise BerError("нет байта длины")
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or pos + n > len(data):
            raise BerError("неподдерживаемая или неполная длина")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return cls, constructed, tag, length, pos


def decode(data: bytes, pos: int = 0) -> tuple[Tlv, int]:
    """Декодирует один элемент BER начиная с позиции pos.

    Возвращает элемент и позицию сразу после него.
    """
    cls, constructed, tag, length, start = read_header(data, pos)
    end = start + length
    if end > len(data):
        raise BerError("значение выходит за границы данных")
    tlv = Tlv(cls, constructed, tag, data[start:end])
    if constructed:
        p = start
        while p < end:
            child, p = decode(data, p)
            tlv.children.append(child)
    return tlv, end


def message_length(data: bytes) -> int | None:
    """Возвращает полную длину первого элемента или None, если данных мало."""
    try:
        _, _, _, length, start = read_header(data)
    except BerError:
        return None
    return start + length


# --------------------------------------------------------------------------
# Кодирование
# --------------------------------------------------------------------------

def _len(n: int) -> bytes:
    """Кодирует длину в короткой или длинной форме."""
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(cls: int, constructed: bool, tag: int, value: bytes) -> bytes:
    """Кодирует произвольный элемент (номер тега меньше 31)."""
    return bytes([(cls << 6) | (0x20 if constructed else 0) | tag]) + _len(len(value)) + value


def integer(v: int, tag: int = INTEGER) -> bytes:
    """Кодирует INTEGER (или ENUMERATED при tag=ENUMERATED)."""
    raw = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(UNIVERSAL, False, tag, raw)


def octets(v: bytes | str) -> bytes:
    """Кодирует OCTET STRING."""
    return tlv(UNIVERSAL, False, OCTET_STRING, v.encode() if isinstance(v, str) else v)


def boolean(v: bool) -> bytes:
    """Кодирует BOOLEAN."""
    return tlv(UNIVERSAL, False, BOOLEAN, b"\xff" if v else b"\x00")


def sequence(*items: bytes) -> bytes:
    """Кодирует SEQUENCE из уже закодированных элементов."""
    return tlv(UNIVERSAL, True, SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    """Кодирует SET OF из уже закодированных элементов."""
    return tlv(UNIVERSAL, True, SET, b"".join(items))
