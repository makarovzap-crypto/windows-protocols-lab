"""Общие компоненты HTTP-серверов стенда (WebDAV и WinRM)."""

from __future__ import annotations

import base64
import http.server
import socketserver
import ssl

from .. import config


class BaseHandler(http.server.BaseHTTPRequestHandler):
    """Базовый обработчик HTTP/1.1 с проверкой обычной (Basic) аутентификации.

    Basic-аутентификация выбрана намеренно: она показывает, что при отсутствии
    TLS имя пользователя и пароль передаются лишь в кодировке Base64.
    """

    protocol_version = "HTTP/1.1"
    server_version = "Microsoft-HTTPAPI/2.0"
    sys_version = ""
    realm = "LAB"

    def log_message(self, fmt: str, *args) -> None:
        """Подавляет вывод журнала запросов в консоль."""

    def read_body(self) -> bytes:
        """Читает тело запроса по заголовку Content-Length."""
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def send_bytes(self, status: int, body: bytes = b"", content_type: str = "text/plain",
                   headers: dict[str, str] | None = None) -> None:
        """Отправляет ответ с указанными статусом, телом и заголовками."""
        self.send_response(status)
        if body or status not in (204, 304):
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def authorized(self) -> bool:
        """Проверяет заголовок Authorization; при ошибке отправляет 401."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                user, _, pwd = base64.b64decode(auth[6:]).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                user, pwd = "", ""
            if user.split("\\")[-1] == config.USERNAME and pwd == config.PASSWORD:
                return True
        self.read_body()
        self.send_bytes(401, b"", headers={"WWW-Authenticate": f'Basic realm="{self.realm}"'})
        return False


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Многопоточный HTTP-сервер."""

    allow_reuse_address = True
    daemon_threads = True


def make_server(port: int, handler: type, tls_context: ssl.SSLContext | None) -> ThreadingServer:
    """Создаёт HTTP- или HTTPS-сервер на 127.0.0.1:port."""
    srv = ThreadingServer((config.LOCALHOST, port), handler)
    if tls_context is not None:
        srv.socket = tls_context.wrap_socket(srv.socket, server_side=True)
    return srv
