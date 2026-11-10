"""Подготовка сертификата и контекстов TLS для защищённых вариантов протоколов.

Стенд использует самоподписанный сертификат сервера dc01.lab.local
(ключ RSA 2048 бит, подпись SHA-256). Он нужен для HTTPS (WebDAV, WinRM),
LDAPS, LDAP StartTLS и Enhanced RDP Security. Проверка сертификата на
клиенте отключена, поскольку удостоверяющий центр в стенде отсутствует;
в реальной инфраструктуре сертификат выпускается корпоративным УЦ
(например, службой Active Directory Certificate Services).
"""

from __future__ import annotations

import datetime
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTNAME = "dc01.lab.local"


def ensure_certificate(directory: str) -> tuple[str, str]:
    """Создаёт самоподписанный сертификат, если его ещё нет.

    Аргументы:
        directory: каталог для файлов server.crt и server.key.
    Возвращает:
        Пути к файлу сертификата и файлу закрытого ключа.
    """
    os.makedirs(directory, exist_ok=True)
    cert_path = os.path.join(directory, "server.crt")
    key_path = os.path.join(directory, "server.key")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LAB stand"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def server_context(cert_path: str, key_path: str, keylog: str | None = None) -> ssl.SSLContext:
    """Создаёт серверный контекст TLS (версия не ниже TLS 1.2).

    Аргументы:
        cert_path, key_path: файлы сертификата и ключа;
        keylog: путь к файлу журнала сеансовых ключей (формат NSS Key Log),
                позволяющий расшифровать трафик в Wireshark.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


def client_context(keylog: str | None = None) -> ssl.SSLContext:
    """Создаёт клиентский контекст TLS без проверки сертификата (только для стенда)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if keylog:
        ctx.keylog_filename = keylog
    return ctx
