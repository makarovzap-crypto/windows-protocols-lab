"""Интеграционный тест: запуск стенда и анализ записанного трафика.

Проверяется основной тезис работы: в открытых вариантах протоколов
учётные данные и содержимое передаются в читаемом виде, а в вариантах
с TLS анализатор видит только параметры рукопожатия.
"""

from __future__ import annotations

import os

import pytest

from stand import analysis, config, runner

SCENARIOS = ["smb", "webdav", "webdav_tls", "ldap", "ldap_starttls", "ldaps", "rdp", "winrm", "winrm_tls"]


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    """Запускает сценарии стенда (кроме WMI/DCOM, зависящего от хоста) и анализирует pcap."""
    out = tmp_path_factory.mktemp("stand")
    results = runner.run(str(out), SCENARIOS)
    assert all(v.startswith("OK") for v in results.values()), results
    return analysis.analyze(os.path.join(out, "windows_protocols.pcap"))


def _by_port(reports, port):
    return [r for r in reports if r.server.endswith(f":{port}")]


def test_every_scenario_recorded(reports):
    """Каждому сценарию соответствует TCP-поток на стандартном порту."""
    ports = sorted(int(r.server.rsplit(":", 1)[1]) for r in reports)
    assert ports == sorted([445, 80, 443, 389, 389, 636, 3389, 5985, 5986])


def test_cleartext_protocols_leak_password(reports):
    """Пароль виден при HTTP Basic (WebDAV, WinRM) и LDAP simple bind без TLS."""
    leaks = [r for r in reports if any(config.PASSWORD in f.evidence for f in r.findings)]
    ports = {int(r.server.rsplit(":", 1)[1]) for r in leaks}
    assert {80, 389, 5985} <= ports


def test_tls_protocols_hide_password(reports):
    """В потоках с TLS пароль и команды не обнаруживаются."""
    for port in (443, 636, 5986, 3389):
        for r in _by_port(reports, port):
            assert r.tls.get("version", "").startswith("TLS"), r.to_dict()
            assert not any(config.PASSWORD in f.evidence for f in r.findings)
    starttls = [r for r in _by_port(reports, 389) if r.encryption.startswith("StartTLS")]
    assert len(starttls) == 1 and not any(config.PASSWORD in f.evidence for f in starttls[0].findings)


def test_psrp_commands_visible_over_http(reports):
    """Команды PowerShell видны при PSRP поверх HTTP (порт 5985)."""
    (winrm,) = _by_port(reports, 5985)
    evidence = " ".join(f.evidence for f in winrm.findings)
    assert "whoami" in evidence and "Get-Service WinRM" in evidence
    assert winrm.messages["PSRP CREATE_PIPELINE"] == 3


def test_smb_file_content_visible(reports):
    """Содержимое файла, записанного по SMB2 без шифрования, видно в трафике."""
    (smb,) = _by_port(reports, 445)
    assert any("Backup#2026" in f.evidence for f in smb.findings)
