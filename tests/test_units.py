"""Модульные тесты компонентов стенда (библиотека тестирования pytest)."""

from __future__ import annotations

import base64
import struct
import uuid

import pytest

from stand import ber, psrp
from stand.analysis import inspectors
from stand.analysis.model import HIGH, MEDIUM, StreamReport
from stand.analysis.streams import Stream, build_streams
from stand.pcap import PcapWriter, TcpSession, checksum, read_tcp_segments
from stand.servers import ldap_server, rdp


def _report(proto: str = "X") -> StreamReport:
    """Пустой отчёт для проверки анализаторов."""
    return StreamReport(0, proto, "c", "s", 0, 0, 0)


def _titles(rep: StreamReport, severity: str) -> list[str]:
    """Заголовки находок указанного уровня."""
    return [f.title for f in rep.findings if f.severity == severity]


# ---------------------------------------------------------------- pcap ----

def test_checksum_rfc1071_example():
    """Контрольная сумма совпадает с примером из RFC 1071."""
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert checksum(data) == (~0xDDF2) & 0xFFFF


def test_pcap_roundtrip_and_stream_reassembly(tmp_path):
    """Записанное TCP-соединение читается и собирается в исходные потоки байтов."""
    path = tmp_path / "t.pcap"
    w = PcapWriter(str(path))
    s = TcpSession(w, ("10.0.0.1", 50000), ("10.0.0.2", 389), b"\x00" * 6, b"\x11" * 6)
    big = bytes(range(256)) * 20          # больше MSS: проверка деления на сегменты
    s.send("c", b"hello")
    s.send("s", big)
    s.send("c", b"bye")
    s.close()
    w.close()
    segs = read_tcp_segments(str(path))
    assert len(segs) >= 10
    (st,) = build_streams(segs)
    assert st.client == ("10.0.0.1", 50000) and st.server == ("10.0.0.2", 389)
    assert st.c2s == b"hellobye" and st.s2c == big
    assert [side for side, _ in st.chunks][0] == "c"


def test_reader_rejects_unknown_format(tmp_path):
    """Файл неизвестного формата вызывает ValueError."""
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"NOTPCAP" * 10)
    with pytest.raises(ValueError):
        read_tcp_segments(str(p))


# ----------------------------------------------------------------- BER ----

def test_ber_roundtrip_long_length():
    """Кодирование и декодирование BER, включая длинную форму длины."""
    payload = "x" * 300
    enc = ber.sequence(ber.integer(7), ber.octets(payload), ber.boolean(True), ber.integer(-2))
    tlv, end = ber.decode(enc)
    assert end == len(enc) and ber.message_length(enc) == len(enc)
    assert tlv.children[0].as_int() == 7
    assert tlv.children[1].as_str() == payload
    assert tlv.children[3].as_int() == -2


def test_ber_incomplete_raises():
    """Обрезанное сообщение распознаётся как неполное."""
    enc = ber.sequence(ber.octets("abc"))
    with pytest.raises(ber.BerError):
        ber.decode(enc[:-1])
    assert ber.message_length(b"\x30") is None


def _filter_eq(attr: str, value: str) -> bytes:
    return ber.tlv(ber.CONTEXT, True, 3, ber.octets(attr) + ber.octets(value))


def test_ldap_filter_matching_and_render():
    """Фильтр (&(objectClass=user)(sAMAccountName=ivanov)) находит одну запись."""
    raw = ber.tlv(ber.CONTEXT, True, 0, _filter_eq("objectClass", "user") + _filter_eq("sAMAccountName", "ivanov"))
    flt, _ = ber.decode(raw)
    hits = [dn for dn, a in ldap_server.DIRECTORY.items() if ldap_server.match_filter(flt, a)]
    assert hits == ["CN=ivanov,OU=Users,DC=lab,DC=local"]
    assert inspectors.ldap_filter(flt) == "(&(objectClass=user)(sAMAccountName=ivanov))"


@pytest.mark.parametrize("dn,base,scope,expected", [
    ("DC=lab,DC=local", "DC=lab,DC=local", 0, True),
    ("OU=Users,DC=lab,DC=local", "DC=lab,DC=local", 1, True),
    ("CN=student,OU=Users,DC=lab,DC=local", "DC=lab,DC=local", 1, False),
    ("CN=student,OU=Users,DC=lab,DC=local", "DC=lab,DC=local", 2, True),
])
def test_ldap_scope(dn, base, scope, expected):
    """Области поиска base, one и sub."""
    assert ldap_server.in_scope(dn, base, scope) is expected


def test_ldap_inspector_finds_simple_bind_password():
    """Анализатор LDAP обнаруживает пароль простой привязки."""
    bind = ber.tlv(ber.APPLICATION, True, 0, ber.integer(3) + ber.octets("CN=a,DC=x")
                   + ber.tlv(ber.CONTEXT, False, 0, b"Secret1"))
    st = Stream(0, ("c", 1), ("s", 389), c2s=ldap_server.envelope(1, bind),
                s2c=ldap_server.envelope(1, ldap_server.result(1, 0)))
    rep = _report()
    inspectors.inspect_ldap(st, rep)
    assert any("Secret1" in f.evidence for f in rep.findings if f.severity == HIGH)
    assert rep.messages["bindRequest"] == 1 and rep.messages["bindResponse"] == 1


# ---------------------------------------------------------------- PSRP ----

def test_psrp_roundtrip():
    """Сообщения PSRP кодируются во фрагменты Base64 и декодируются обратно."""
    rpid, pid = uuid.uuid4(), uuid.uuid4()
    blob = psrp.encode_messages([
        psrp.build_message(psrp.DEST_SERVER, psrp.CREATE_PIPELINE, rpid, pid, psrp.create_pipeline("Get-Date")),
        psrp.build_message(psrp.DEST_CLIENT, psrp.PIPELINE_OUTPUT, rpid, pid, psrp.pipeline_output("ok & <done>")),
    ])
    msgs = psrp.decode_blob(blob)
    assert [m.type_name for m in msgs] == ["CREATE_PIPELINE", "PIPELINE_OUTPUT"]
    assert msgs[0].rpid == rpid and msgs[0].pid == pid
    assert '<S N="Cmd">Get-Date</S>' in msgs[0].data
    assert psrp.clixml_strings(msgs[1].data) == ["ok &amp; &lt;done&gt;"]


# ---------------------------------------------------------------- HTTP ----

def test_http_parser_content_length_and_chunked():
    """Разбор сообщений HTTP с Content-Length и chunked."""
    data = (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
            b"HTTP/1.1 207 Multi-Status\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nxy\r\n1\r\nz\r\n0\r\n\r\n")
    msgs = inspectors.parse_http(data)
    assert [m[2] for m in msgs] == [b"abc", b"xyz"]


def test_http_inspector_basic_auth_decoded():
    """Анализатор HTTP декодирует учётные данные Basic."""
    auth = base64.b64encode(b"LAB\\u:pw").decode()
    req = f"PUT /f.txt HTTP/1.1\r\nAuthorization: Basic {auth}\r\nContent-Length: 4\r\n\r\ndata".encode()
    st = Stream(0, ("c", 1), ("s", 80), c2s=req, s2c=b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
    rep = _report()
    inspectors.inspect_http(st, rep)
    assert any("LAB\\u:pw" in f.evidence for f in rep.findings)
    assert "Содержимое загружаемого файла передано в открытом виде" in _titles(rep, HIGH)


# ----------------------------------------------------------------- RDP ----

def test_rdp_negotiation_parsing():
    """Разбор X.224 Connection Request/Confirm и cookie mstshash."""
    cr = rdp.connection_request("alice", rdp.PROTOCOL_SSL | rdp.PROTOCOL_HYBRID)
    cc = rdp.connection_confirm(rdp.PROTOCOL_SSL)
    assert struct.unpack("!H", cr[2:4])[0] == len(cr)
    st = Stream(0, ("c", 1), ("s", 3389), c2s=cr, s2c=cc)
    rep = _report()
    inspectors.inspect_rdp(st, rep)
    ev = {f.title: f.evidence for f in rep.findings}
    assert ev["Имя пользователя в поле Cookie (mstshash) передаётся открыто"] == "alice"
    assert ev["Сервер выбрал протокол безопасности (RDP_NEG_RSP)"] == "TLS"


# ----------------------------------------------------------------- SMB ----

def test_smb_write_and_tree_connect():
    """Анализатор SMB2 извлекает путь ресурса и данные записи."""
    def smb2(cmd: int, body: bytes, resp: bool = False) -> bytes:
        hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ16s", 64, 0, 0, cmd, 1, int(resp), 0, 1, 0, 0, 0, b"")
        msg = hdr + body
        return b"\x00" + len(msg).to_bytes(3, "big") + msg
    path = "\\\\DC01\\LAB".encode("utf-16-le")
    tree = smb2(3, struct.pack("<HHHH", 9, 0, 72, len(path)) + path)
    data = b"secret-data"
    write = smb2(9, struct.pack("<HHIQ16sIIHHI", 49, 112, len(data), 0, b"", 0, 0, 0, 0, 0) + data)
    st = Stream(0, ("c", 1), ("s", 445), c2s=tree + write, s2c=b"")
    rep = _report()
    inspectors.inspect_smb(st, rep)
    assert "\\\\DC01\\LAB" in [f.evidence for f in rep.findings if f.severity == MEDIUM]
    assert any("secret-data" in f.evidence for f in rep.findings if f.severity == HIGH)


# ----------------------------------------------------------------- TLS ----

def test_tls_detection():
    """Распознавание записи TLS Handshake."""
    assert inspectors.is_tls(b"\x16\x03\x01\x00\x10")
    assert not inspectors.is_tls(b"GET / HTTP/1.1")
