"""Общая конфигурация стенда.

Модуль содержит учётные данные тестового пользователя, сетевые порты
локальных серверов и параметры «виртуальной» сети, которая используется
при записи трафика в файл захвата (pcap).

Каждый сервис стенда описывается тремя портами:
    real_port    – порт, на котором реально слушает учебный сервер (127.0.0.1);
    proxy_port   – порт записывающего прокси, к которому подключается клиент;
    virtual_port – стандартный порт протокола, который указывается в pcap,
                   чтобы Wireshark автоматически применил нужный диссектор.
"""

from dataclasses import dataclass

# Учётные данные тестового пользователя (используются только внутри стенда).
DOMAIN = "LAB"
USERNAME = "student"
PASSWORD = "P@ssw0rd2026"
USER_DN = "CN=student,OU=Users,DC=lab,DC=local"
BASE_DN = "DC=lab,DC=local"

# Параметры виртуальной сети, отображаемые в pcap.
CLIENT_IP = "192.168.56.10"     # рабочая станция WS01
SERVER_IP = "192.168.56.2"      # сервер DC01
CLIENT_MAC = bytes.fromhex("0800271a2b10")
SERVER_MAC = bytes.fromhex("0800271a2b02")

LOCALHOST = "127.0.0.1"


@dataclass(frozen=True)
class Service:
    """Описание одного сервиса стенда.

    Атрибуты:
        name: краткое имя сервиса (используется в журналах и отчёте);
        protocol: протокол прикладного уровня;
        real_port: порт учебного сервера на 127.0.0.1;
        proxy_port: порт записывающего прокси;
        virtual_port: стандартный порт протокола в файле захвата;
        tls: признак использования шифрования TLS поверх TCP;
        real_host: адрес реального сервера (по умолчанию 127.0.0.1).
    """

    name: str
    protocol: str
    real_port: int
    proxy_port: int
    virtual_port: int
    tls: bool = False
    real_host: str = LOCALHOST


SERVICES = {
    "smb": Service("smb", "SMB2", 14450, 24450, 445),
    "webdav": Service("webdav", "WebDAV", 18080, 28080, 80),
    "webdav_tls": Service("webdav_tls", "WebDAV", 18443, 28443, 443, tls=True),
    "ldap": Service("ldap", "LDAP", 13890, 23890, 389),
    "ldap_starttls": Service("ldap_starttls", "LDAP", 13891, 23891, 389, tls=True),
    "ldaps": Service("ldaps", "LDAP", 16360, 26360, 636, tls=True),
    "rdp": Service("rdp", "RDP", 13389, 23389, 3389, tls=True),
    "winrm": Service("winrm", "WinRM", 15985, 25985, 5985),
    "winrm_tls": Service("winrm_tls", "WinRM", 15986, 25986, 5986, tls=True),
    # WMI/DCOM: обращение к настоящей службе RPC Endpoint Mapper хоста (порт 135).
    "wmi_dcom": Service("wmi_dcom", "DCE/RPC (WMI/DCOM)", 135, 21350, 135),
}
