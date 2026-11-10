"""Учебный сервер WebDAV (RFC 4918) с хранилищем в оперативной памяти.

Реализованы методы OPTIONS, PROPFIND, MKCOL, PUT, GET, HEAD, DELETE,
COPY, MOVE, LOCK и UNLOCK. Ответы на PROPFIND формируются в виде
XML-документа multistatus с кодом 207, как это делают IIS и служба
WebClient в операционных системах семейства Windows.
"""

from __future__ import annotations

import email.utils
import threading
import time
import uuid
from urllib.parse import unquote, urlparse
from xml.sax.saxutils import escape

from .http_common import BaseHandler

_store: dict[str, bytes] = {}          # путь файла -> содержимое
_collections: set[str] = {"/"}         # пути каталогов (коллекций)
_locks: dict[str, str] = {}            # путь -> маркер блокировки
_mutex = threading.Lock()


def _norm(path: str) -> str:
    """Нормализует путь запроса: декодирует %XX и убирает завершающий '/'."""
    p = unquote(urlparse(path).path) or "/"
    return p.rstrip("/") or "/"


def _propstat(href: str, is_dir: bool, size: int) -> str:
    """Формирует элемент <D:response> со стандартными свойствами ресурса."""
    rtype = "<D:collection/>" if is_dir else ""
    date = email.utils.formatdate(time.time(), usegmt=True)
    length = "" if is_dir else f"<D:getcontentlength>{size}</D:getcontentlength>"
    return (f"<D:response><D:href>{escape(href)}</D:href><D:propstat><D:prop>"
            f"<D:displayname>{escape(href.rstrip('/').split('/')[-1])}</D:displayname>"
            f"<D:resourcetype>{rtype}</D:resourcetype>{length}"
            f"<D:getlastmodified>{date}</D:getlastmodified>"
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")


class WebDavHandler(BaseHandler):
    """Обработчик запросов WebDAV."""

    def do_OPTIONS(self) -> None:
        """Сообщает поддерживаемые методы и классы соответствия WebDAV."""
        self.read_body()
        self.send_bytes(200, headers={
            "DAV": "1,2", "MS-Author-Via": "DAV",
            "Allow": "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"})

    def do_PROPFIND(self) -> None:
        """Возвращает свойства ресурса и (при Depth: 1) его дочерних элементов."""
        if not self.authorized():
            return
        self.read_body()
        path = _norm(self.path)
        depth = self.headers.get("Depth", "1")
        with _mutex:
            if path not in _collections and path not in _store:
                self.send_bytes(404)
                return
            items = [_propstat(path + ("/" if path in _collections and path != "/" else ""),
                               path in _collections, len(_store.get(path, b"")))]
            if path in _collections and depth != "0":
                prefix = path.rstrip("/") + "/"
                for p in sorted(_collections | set(_store)):
                    if p != path and p.startswith(prefix) and "/" not in p[len(prefix):]:
                        items.append(_propstat(p + ("/" if p in _collections else ""),
                                               p in _collections, len(_store.get(p, b""))))
        body = ('<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">'
                + "".join(items) + "</D:multistatus>").encode()
        self.send_bytes(207, body, 'application/xml; charset="utf-8"')

    def do_MKCOL(self) -> None:
        """Создаёт коллекцию (каталог)."""
        if not self.authorized():
            return
        self.read_body()
        path = _norm(self.path)
        with _mutex:
            exists = path in _collections or path in _store
            if not exists:
                _collections.add(path)
        self.send_bytes(405 if exists else 201)

    def do_PUT(self) -> None:
        """Сохраняет содержимое файла."""
        if not self.authorized():
            return
        data = self.read_body()
        path = _norm(self.path)
        with _mutex:
            created = path not in _store
            _store[path] = data
        self.send_bytes(201 if created else 204)

    def do_GET(self) -> None:
        """Возвращает содержимое файла."""
        if not self.authorized():
            return
        path = _norm(self.path)
        with _mutex:
            data = _store.get(path)
        if data is None:
            self.send_bytes(404)
        else:
            self.send_bytes(200, data, "application/octet-stream")

    do_HEAD = do_GET

    def do_DELETE(self) -> None:
        """Удаляет файл или коллекцию."""
        if not self.authorized():
            return
        self.read_body()
        path = _norm(self.path)
        with _mutex:
            found = _store.pop(path, None) is not None or path in _collections
            _collections.discard(path)
        self.send_bytes(204 if found else 404)

    def _copy_or_move(self, move: bool) -> None:
        """Общая реализация методов COPY и MOVE (заголовок Destination)."""
        if not self.authorized():
            return
        self.read_body()
        src, dst = _norm(self.path), _norm(self.headers.get("Destination", ""))
        with _mutex:
            if src not in _store:
                self.send_bytes(404)
                return
            created = dst not in _store
            _store[dst] = _store[src]
            if move:
                del _store[src]
        self.send_bytes(201 if created else 204)

    def do_COPY(self) -> None:
        """Копирует файл."""
        self._copy_or_move(False)

    def do_MOVE(self) -> None:
        """Перемещает (переименовывает) файл."""
        self._copy_or_move(True)

    def do_LOCK(self) -> None:
        """Устанавливает монопольную блокировку и возвращает её маркер."""
        if not self.authorized():
            return
        self.read_body()
        token = f"opaquelocktoken:{uuid.uuid4()}"
        with _mutex:
            _locks[_norm(self.path)] = token
        body = ('<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery>'
                '<D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/>'
                '</D:lockscope><D:depth>0</D:depth><D:timeout>Second-3600</D:timeout>'
                f'<D:locktoken><D:href>{token}</D:href></D:locktoken></D:activelock>'
                '</D:lockdiscovery></D:prop>').encode()
        self.send_bytes(200, body, 'application/xml; charset="utf-8"', {"Lock-Token": f"<{token}>"})

    def do_UNLOCK(self) -> None:
        """Снимает блокировку."""
        if not self.authorized():
            return
        self.read_body()
        with _mutex:
            _locks.pop(_norm(self.path), None)
        self.send_bytes(204)
