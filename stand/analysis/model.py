"""Структуры данных результатов анализа."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

# Уровни значимости находок.
HIGH = "ВЫСОКИЙ"      # раскрытие учётных данных, команд или содержимого файлов
MEDIUM = "СРЕДНИЙ"    # раскрытие служебных сведений (имена, структура каталога)
INFO = "ИНФО"         # справочные сведения о параметрах протокола


@dataclass
class Finding:
    """Находка: сведение, видимое в перехваченном трафике.

    Атрибуты:
        severity: уровень значимости (HIGH, MEDIUM, INFO);
        title: краткое описание;
        evidence: фрагмент данных из трафика, подтверждающий находку.
    """

    severity: str
    title: str
    evidence: str = ""


@dataclass
class StreamReport:
    """Результат анализа одного TCP-потока.

    Атрибуты:
        index: номер потока (совпадает с tcp.stream в Wireshark);
        protocol: определённый прикладной протокол;
        client, server: конечные точки «адрес:порт»;
        packets, bytes_c2s, bytes_s2c: объём обмена;
        encryption: описание защиты канала;
        tls: параметры TLS (версия, набор шифров, SNI), если применяется;
        messages: счётчик типов сообщений прикладного протокола;
        findings: перечень находок.
    """

    index: int
    protocol: str
    client: str
    server: str
    packets: int
    bytes_c2s: int
    bytes_s2c: int
    encryption: str = "нет"
    tls: dict = field(default_factory=dict)
    messages: Counter = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: str, title: str, evidence: str = "") -> None:
        """Добавляет находку, исключая точные повторы."""
        f = Finding(severity, title, evidence)
        if f not in self.findings:
            self.findings.append(f)

    def to_dict(self) -> dict:
        """Преобразует отчёт в словарь для сериализации в JSON."""
        return {
            "stream": self.index, "protocol": self.protocol, "client": self.client,
            "server": self.server, "packets": self.packets, "bytes_c2s": self.bytes_c2s,
            "bytes_s2c": self.bytes_s2c, "encryption": self.encryption, "tls": self.tls,
            "messages": dict(self.messages),
            "findings": [f.__dict__ for f in self.findings],
        }


def preview(data: bytes | str, limit: int = 120) -> str:
    """Возвращает укороченное однострочное представление данных."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    data = " ".join(data.split())
    return data if len(data) <= limit else data[:limit] + "…"
