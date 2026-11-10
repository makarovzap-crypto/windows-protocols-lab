"""Учебный сервер LDAPv3 (RFC 4511), имитирующий каталог Active Directory.

Поддерживаемые операции:
  * BindRequest с простой аутентификацией (simple bind);
  * SearchRequest с фильтрами equalityMatch, present, substrings, and, or, not;
  * ExtendedRequest StartTLS (OID 1.3.6.1.4.1.1466.20037) – переход на TLS;
  * UnbindRequest.
Сервер может работать в трёх режимах: открытый LDAP (порт 389),
LDAP с обязательным StartTLS и LDAPS (TLS с момента подключения, порт 636).
"""

from __future__ import annotations

import logging
import socket
import socketserver
import ssl

from .. import ber, config

log = logging.getLogger("ldap")

# Номера операций LDAP (тег класса APPLICATION).
OPS = {
    0: "bindRequest", 1: "bindResponse", 2: "unbindRequest", 3: "searchRequest",
    4: "searchResEntry", 5: "searchResDone", 6: "modifyRequest", 7: "modifyResponse",
    8: "addRequest", 9: "addResponse", 10: "delRequest", 11: "delResponse",
    12: "modDNRequest", 13: "modDNResponse", 14: "compareRequest", 15: "compareResponse",
    16: "abandonRequest", 19: "searchResRef", 23: "extendedRequest", 24: "extendedResponse",
}
STARTTLS_OID = "1.3.6.1.4.1.1466.20037"

# Содержимое учебного каталога: DN -> атрибуты (значения – списки строк).
DIRECTORY: dict[str, dict[str, list[str]]] = {
    config.BASE_DN: {"objectClass": ["top", "domain"], "dc": ["lab"]},
    "OU=Users,DC=lab,DC=local": {"objectClass": ["top", "organizationalUnit"], "ou": ["Users"]},
    config.USER_DN: {
        "objectClass": ["top", "person", "user"], "cn": ["student"],
        "sAMAccountName": ["student"], "displayName": ["Студент Практики"],
        "mail": ["student@lab.local"], "memberOf": ["CN=Remote Management Users,CN=Builtin,DC=lab,DC=local"],
        "userPassword": [config.PASSWORD],
    },
    "CN=ivanov,OU=Users,DC=lab,DC=local": {
        "objectClass": ["top", "person", "user"], "cn": ["ivanov"],
        "sAMAccountName": ["ivanov"], "displayName": ["Иванов Иван"],
        "mail": ["ivanov@lab.local"], "title": ["Системный администратор"],
        "memberOf": ["CN=Domain Admins,CN=Users,DC=lab,DC=local"],
    },
    "CN=DC01,OU=Domain Controllers,DC=lab,DC=local": {
        "objectClass": ["top", "computer"], "cn": ["DC01"],
        "dNSHostName": ["dc01.lab.local"], "operatingSystem": ["Windows Server 2022 Standard"],
    },
}


def match_filter(flt: ber.Tlv, attrs: dict[str, list[str]]) -> bool:
    """Проверяет запись каталога на соответствие фильтру поиска LDAP.

    Аргументы:
        flt: декодированный фильтр (CHOICE с контекстными тегами);
        attrs: атрибуты проверяемой записи.
    """
    lower = {k.lower(): [v.lower() for v in vals] for k, vals in attrs.items()}
    t = flt.tag
    if t == 0:   # and
        return all(match_filter(c, attrs) for c in flt.children)
    if t == 1:   # or
        return any(match_filter(c, attrs) for c in flt.children)
    if t == 2:   # not
        return not match_filter(flt.children[0], attrs)
    if t == 3:   # equalityMatch
        name, value = flt.children[0].as_str().lower(), flt.children[1].as_str().lower()
        return value in lower.get(name, [])
    if t == 4:   # substrings
        name = flt.children[0].as_str().lower()
        parts = [(c.tag, c.as_str().lower()) for c in flt.children[1].children]
        for val in lower.get(name, []):
            ok, pos = True, 0
            for kind, s in parts:
                if kind == 0:
                    ok = val.startswith(s)
                    pos = len(s)
                elif kind == 1:
                    idx = val.find(s, pos)
                    ok = idx >= 0
                    pos = idx + len(s)
                else:
                    ok = val.endswith(s)
                if not ok:
                    break
            if ok:
                return True
        return False
    if t == 7:   # present
        return flt.as_str().lower() in lower
    return False


def in_scope(dn: str, base: str, scope: int) -> bool:
    """Проверяет, входит ли запись dn в область поиска (0 – base, 1 – one, 2 – sub)."""
    dn_l, base_l = dn.lower(), base.lower()
    if scope == 0:
        return dn_l == base_l
    if not base_l:
        return scope == 2 or dn_l.count(",") == 0
    if not dn_l.endswith("," + base_l):
        return scope == 2 and dn_l == base_l
    if scope == 1:
        return dn_l[: -len(base_l) - 1].count(",") == 0
    return True


def result(op: int, code: int, message: str = "", extra: bytes = b"") -> bytes:
    """Кодирует ответ LDAPResult (resultCode, matchedDN, diagnosticMessage)."""
    body = ber.integer(code, ber.ENUMERATED) + ber.octets("") + ber.octets(message) + extra
    return ber.tlv(ber.APPLICATION, True, op, body)


def envelope(msg_id: int, op: bytes) -> bytes:
    """Упаковывает операцию в LDAPMessage с идентификатором msg_id."""
    return ber.sequence(ber.integer(msg_id), op)


def recv_message(sock: socket.socket) -> bytes | None:
    """Читает из сокета одно полное сообщение BER; None при закрытии соединения."""
    buf = b""
    while True:
        need = ber.message_length(buf)
        if need is not None and len(buf) >= need:
            return buf
        chunk = sock.recv(need - len(buf) if need else 1)
        if not chunk:
            return None
        buf += chunk


class LdapHandler(socketserver.BaseRequestHandler):
    """Обработчик одного LDAP-подключения."""

    tls_context: ssl.SSLContext | None = None
    implicit_tls = False   # True – LDAPS (TLS сразу после подключения)

    def handle(self) -> None:
        """Цикл чтения запросов и отправки ответов."""
        sock = self.request
        if self.implicit_tls:
            sock = self.tls_context.wrap_socket(sock, server_side=True)
        bound_dn = ""
        while True:
            raw = recv_message(sock)
            if raw is None:
                return
            msg, _ = ber.decode(raw)
            msg_id = msg.children[0].as_int()
            op = msg.children[1]
            name = OPS.get(op.tag, str(op.tag))
            log.debug("LDAP %s id=%s", name, msg_id)
            if op.tag == 0:      # bindRequest
                dn = op.children[1].as_str()
                auth = op.children[2]
                password = auth.value.decode("utf-8", "replace") if auth.tag == 0 else ""
                stored = DIRECTORY.get(dn, {}).get("userPassword", [None])[0]
                if dn == "" or (stored is not None and stored == password):
                    bound_dn = dn
                    sock.sendall(envelope(msg_id, result(1, 0)))
                else:
                    sock.sendall(envelope(msg_id, result(1, 49, "80090308: LdapErr: DSID-0C09044E, "
                                                             "comment: AcceptSecurityContext error, data 52e")))
            elif op.tag == 3:    # searchRequest
                base = op.children[0].as_str()
                scope = op.children[1].as_int()
                flt = op.children[6]
                wanted = {c.as_str().lower() for c in op.children[7].children}
                for dn, attrs in DIRECTORY.items():
                    if not in_scope(dn, base, scope) or not match_filter(flt, attrs):
                        continue
                    parts = []
                    for k, vals in attrs.items():
                        if k == "userPassword" or (wanted and "*" not in wanted and k.lower() not in wanted):
                            continue
                        parts.append(ber.sequence(ber.octets(k), ber.set_of(*[ber.octets(v) for v in vals])))
                    entry = ber.tlv(ber.APPLICATION, True, 4, ber.octets(dn) + ber.sequence(*parts))
                    sock.sendall(envelope(msg_id, entry))
                code = 0 if bound_dn or base == "" else 1
                sock.sendall(envelope(msg_id, result(5, code)))
            elif op.tag == 23:   # extendedRequest
                oid = op.children[0].as_str() if op.children else ""
                if oid == STARTTLS_OID and self.tls_context is not None:
                    name_tlv = ber.tlv(ber.CONTEXT, False, 10, STARTTLS_OID.encode())
                    sock.sendall(envelope(msg_id, result(24, 0, extra=name_tlv)))
                    sock = self.tls_context.wrap_socket(sock, server_side=True)
                else:
                    sock.sendall(envelope(msg_id, result(24, 2, "unsupported extended operation")))
            elif op.tag == 2:    # unbindRequest
                return
            else:
                sock.sendall(envelope(msg_id, result(op.tag + 1, 53, "unwilling to perform")))


class _Server(socketserver.ThreadingTCPServer):
    """Многопоточный TCP-сервер с повторным использованием адреса."""

    allow_reuse_address = True
    daemon_threads = True


def make_server(port: int, tls_context: ssl.SSLContext | None, implicit_tls: bool) -> _Server:
    """Создаёт экземпляр LDAP-сервера.

    Аргументы:
        port: порт прослушивания на 127.0.0.1;
        tls_context: серверный контекст TLS (для StartTLS и LDAPS);
        implicit_tls: True – режим LDAPS.
    """
    handler = type("Handler", (LdapHandler,), {"tls_context": tls_context,
                                               "implicit_tls": implicit_tls})
    return _Server((config.LOCALHOST, port), handler)
