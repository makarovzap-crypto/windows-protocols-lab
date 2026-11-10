"""Сообщения PowerShell Remoting Protocol (MS-PSRP).

PSRP передаёт данные внутри SOAP-сообщений WinRM: блоки creationXml,
Arguments и Stream содержат закодированные в Base64 фрагменты (fragment),
а фрагменты – сообщения PSRP. Сообщение состоит из заголовка
(получатель, тип, идентификаторы пула и конвейера) и данных в формате
CLIXML – XML-сериализации объектов .NET.

Структура фрагмента (порядок байт big-endian):
    ObjectId (8) | FragmentId (8) | флаги S/E (1) | BlobLength (4) | Blob
Структура сообщения (порядок байт little-endian):
    Destination (4) | MessageType (4) | RPID (16) | PID (16) | Data
"""

from __future__ import annotations

import base64
import re
import struct
import uuid
from dataclasses import dataclass

DEST_CLIENT, DEST_SERVER = 1, 2

MESSAGE_TYPES = {
    0x00010002: "SESSION_CAPABILITY",
    0x00010004: "INIT_RUNSPACEPOOL",
    0x00010005: "PUBLIC_KEY",
    0x00010006: "ENCRYPTED_SESSION_KEY",
    0x00010007: "PUBLIC_KEY_REQUEST",
    0x00021002: "SET_MAX_RUNSPACES",
    0x00021005: "RUNSPACEPOOL_STATE",
    0x00021006: "CREATE_PIPELINE",
    0x00021009: "APPLICATION_PRIVATE_DATA",
    0x00041002: "PIPELINE_INPUT",
    0x00041004: "PIPELINE_OUTPUT",
    0x00041005: "ERROR_RECORD",
    0x00041006: "PIPELINE_STATE",
}
SESSION_CAPABILITY = 0x00010002
INIT_RUNSPACEPOOL = 0x00010004
RUNSPACEPOOL_STATE = 0x00021005
CREATE_PIPELINE = 0x00021006
PIPELINE_OUTPUT = 0x00041004
PIPELINE_STATE = 0x00041006

BOM = b"\xef\xbb\xbf"


@dataclass
class PsrpMessage:
    """Декодированное сообщение PSRP."""

    destination: int
    message_type: int
    rpid: uuid.UUID
    pid: uuid.UUID
    data: str

    @property
    def type_name(self) -> str:
        """Символьное имя типа сообщения."""
        return MESSAGE_TYPES.get(self.message_type, hex(self.message_type))


def build_message(destination: int, message_type: int, rpid: uuid.UUID,
                  pid: uuid.UUID | None, clixml: str) -> bytes:
    """Кодирует сообщение PSRP (данные CLIXML в UTF-8 с BOM)."""
    pid = pid or uuid.UUID(int=0)
    return (struct.pack("<II", destination, message_type) + rpid.bytes_le + pid.bytes_le
            + BOM + clixml.encode("utf-8"))


def build_fragment(object_id: int, message: bytes) -> bytes:
    """Упаковывает сообщение в один фрагмент (флаги Start и End)."""
    return struct.pack(">QQBI", object_id, 0, 0x03, len(message)) + message


def encode_messages(messages: list[bytes], first_object_id: int = 1) -> str:
    """Кодирует набор сообщений во фрагменты и далее в строку Base64."""
    blob = b"".join(build_fragment(first_object_id + i, m) for i, m in enumerate(messages))
    return base64.b64encode(blob).decode()


def decode_blob(b64: str) -> list[PsrpMessage]:
    """Декодирует строку Base64 с фрагментами PSRP в список сообщений.

    Фрагменты одного объекта (ObjectId) объединяются перед разбором.
    """
    raw = base64.b64decode(re.sub(r"\s+", "", b64))
    pos, parts = 0, {}
    order: list[int] = []
    while pos + 21 <= len(raw):
        obj, _frag, _flags, blen = struct.unpack(">QQBI", raw[pos:pos + 21])
        pos += 21
        if obj not in parts:
            parts[obj] = b""
            order.append(obj)
        parts[obj] += raw[pos:pos + blen]
        pos += blen
    out = []
    for obj in order:
        m = parts[obj]
        if len(m) < 40:
            continue
        dest, mtype = struct.unpack("<II", m[:8])
        data = m[40:]
        if data.startswith(BOM):
            data = data[3:]
        out.append(PsrpMessage(dest, mtype, uuid.UUID(bytes_le=m[8:24]),
                               uuid.UUID(bytes_le=m[24:40]), data.decode("utf-8", "replace")))
    return out


def clixml_strings(clixml: str) -> list[str]:
    """Извлекает строковые значения (элементы <S>) из CLIXML."""
    return [re.sub(r"_x([0-9A-Fa-f]{4})_", lambda m: chr(int(m.group(1), 16)), s)
            for s in re.findall(r"<S(?: [^>]*)?>([^<]*)</S>", clixml)]


# --------------------------------------------------------------------------
# Шаблоны CLIXML для типовых сообщений
# --------------------------------------------------------------------------

def session_capability() -> str:
    """CLIXML сообщения SESSION_CAPABILITY (версии протокола и PowerShell)."""
    return ('<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version>'
            '<Version N="PSVersion">2.0</Version>'
            '<Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>')


def init_runspacepool() -> str:
    """CLIXML сообщения INIT_RUNSPACEPOOL (минимальный и максимальный размер пула)."""
    return ('<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32>'
            '<Obj N="PSThreadOptions" RefId="1"><ToString>Default</ToString><I32>0</I32></Obj>'
            '<Obj N="ApartmentState" RefId="2"><ToString>Unknown</ToString><I32>2</I32></Obj>'
            '<Obj N="HostInfo" RefId="3"><MS><B N="_isHostNull">true</B></MS></Obj>'
            '<Nil N="ApplicationArguments" /></MS></Obj>')


def create_pipeline(script: str) -> str:
    """CLIXML сообщения CREATE_PIPELINE с одной командой-скриптом."""
    from xml.sax.saxutils import escape
    return ('<Obj RefId="0"><MS><B N="NoInput">true</B><B N="AddToHistory">false</B>'
            '<B N="IsNested">false</B><Obj N="PowerShell" RefId="1"><MS>'
            '<B N="IsNested">false</B><Obj N="Cmds" RefId="2"><LST><Obj RefId="3"><MS>'
            f'<S N="Cmd">{escape(script)}</S><B N="IsScript">true</B><Nil N="UseLocalScope" />'
            '<Obj N="Args" RefId="4"><LST /></Obj></MS></Obj></LST></Obj></MS></Obj></MS></Obj>')


def runspace_state(state: int = 2) -> str:
    """CLIXML сообщения RUNSPACEPOOL_STATE (2 – Opened)."""
    return f'<Obj RefId="0"><MS><I32 N="RunspaceState">{state}</I32></MS></Obj>'


def pipeline_output(text: str) -> str:
    """CLIXML сообщения PIPELINE_OUTPUT со строковым результатом."""
    from xml.sax.saxutils import escape
    return f"<S>{escape(text)}</S>"


def pipeline_state(state: int = 4) -> str:
    """CLIXML сообщения PIPELINE_STATE (4 – Completed)."""
    return f'<Obj RefId="0"><MS><I32 N="PipelineState">{state}</I32></MS></Obj>'
