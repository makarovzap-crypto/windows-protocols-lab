"""Учебный сервер начальной фазы протокола RDP (MS-RDPBCGR).

Сервер выполняет согласование протокола безопасности:
  1. принимает X.224 Connection Request (TPKT) с полем Cookie
     («mstshash=<имя пользователя>») и структурой RDP_NEG_REQ;
  2. отвечает X.224 Connection Confirm со структурой RDP_NEG_RSP,
     выбирая Enhanced RDP Security (TLS);
  3. выполняет рукопожатие TLS и принимает зашифрованное сообщение
     MCS Connect Initial, после чего завершает соединение.
Этого достаточно, чтобы показать, какие сведения RDP передаёт открыто
до установления защищённого канала.
"""

from __future__ import annotations

import socketserver
import ssl
import struct

from .. import config

# Флаги requestedProtocols / selectedProtocol.
PROTOCOL_RDP = 0x0          # Standard RDP Security (RC4)
PROTOCOL_SSL = 0x1          # TLS
PROTOCOL_HYBRID = 0x2       # CredSSP (NLA)
PROTOCOL_RDSTLS = 0x4
PROTOCOL_HYBRID_EX = 0x8


def tpkt(payload: bytes) -> bytes:
    """Упаковывает данные в заголовок TPKT (RFC 1006): версия 3, длина пакета."""
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


def connection_request(cookie_user: str, requested: int) -> bytes:
    """Формирует X.224 Connection Request с Cookie и RDP_NEG_REQ."""
    cookie = f"Cookie: mstshash={cookie_user}\r\n".encode()
    neg = struct.pack("<BBHI", 0x01, 0, 8, requested)
    body = bytes([0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    return tpkt(bytes([len(body)]) + body)


def connection_confirm(selected: int) -> bytes:
    """Формирует X.224 Connection Confirm с RDP_NEG_RSP."""
    neg = struct.pack("<BBHI", 0x02, 0x1F, 8, selected)
    body = bytes([0xD0, 0, 0, 0x12, 0x34, 0]) + neg
    return tpkt(bytes([len(body)]) + body)


def read_tpkt(sock) -> bytes:
    """Читает из сокета один пакет TPKT целиком."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return b""
        hdr += chunk
    length = struct.unpack("!H", hdr[2:4])[0]
    data = b""
    while len(data) < length - 4:
        chunk = sock.recv(length - 4 - len(data))
        if not chunk:
            break
        data += chunk
    return hdr + data


class RdpHandler(socketserver.BaseRequestHandler):
    """Обработчик одного RDP-подключения."""

    tls_context: ssl.SSLContext

    def handle(self) -> None:
        """Выполняет согласование безопасности и переход на TLS."""
        request = read_tpkt(self.request)
        if len(request) < 19:
            return
        requested = struct.unpack("<I", request[-4:])[0]
        selected = PROTOCOL_SSL if requested & PROTOCOL_SSL else PROTOCOL_RDP
        self.request.sendall(connection_confirm(selected))
        if selected != PROTOCOL_SSL:
            return
        tls = self.tls_context.wrap_socket(self.request, server_side=True)
        read_tpkt(tls)  # MCS Connect Initial (внутри TLS)
        # Ответ-заглушка MCS Connect Response: в стенде достаточно факта передачи.
        tls.sendall(tpkt(b"\x02\xf0\x80" + b"\x7f\x66\x82\x00\x10" + b"\x0a\x01\x00" + bytes(13)))
        try:
            tls.unwrap()
        except (ssl.SSLError, OSError):
            pass


class _Server(socketserver.ThreadingTCPServer):
    """Многопоточный TCP-сервер."""

    allow_reuse_address = True
    daemon_threads = True


def make_server(port: int, tls_context: ssl.SSLContext) -> _Server:
    """Создаёт RDP-сервер на 127.0.0.1:port."""
    handler = type("Handler", (RdpHandler,), {"tls_context": tls_context})
    return _Server((config.LOCALHOST, port), handler)
