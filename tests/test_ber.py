import pytest

from kdsextract import ber

def test_integer():
    assert ber.integer(0) == bytes.fromhex("02 01 00")
    assert ber.integer(3) == bytes.fromhex("02 01 03")
    assert ber.integer(127) == bytes.fromhex("02 01 7f")
    assert ber.integer(128) == bytes.fromhex("02 02 00 80")
    assert ber.integer(-1) == bytes.fromhex("02 01 ff")
    assert ber.integer(65535) == bytes.fromhex("02 03 00 ff ff")

def test_enumerated_and_bool():
    assert ber.enumerated(2) == bytes.fromhex("0a 01 02")
    assert ber.boolean(True) == bytes.fromhex("01 01 ff")

def test_octet_string():
    assert ber.octet_string(b"ab") == bytes.fromhex("04 02 61 62")
    long = ber.octet_string(b"x" * 300)
    assert long[0] == 0x04 and long[1] == 0x82 and long[2] == 0x01 and long[3] == 0x2C

def test_sequence_and_tagging():
    assert ber.sequence(ber.integer(1)) == bytes.fromhex("30 03 02 01 01")
    app3 = ber.application(3, b"")
    assert app3 == bytes.fromhex("63 00")
    ctx3 = ber.context(3, b"a", b"b")
    assert ctx3[0] == 0xA3
    prim7 = ber.context(7, b"cn", constructed=False)
    assert prim7 == bytes.fromhex("87 02 63 6e")

def test_decode_roundtrip():
    raw = ber.sequence(
        ber.integer(42),
        ber.application(
            14,
            ber.octet_string(b"dc=x"),
            ber.sequence(ber.octet_string(b"a"), ber.octet_string(b"b")),
        ),
    )
    msg = ber.decode(raw)
    assert msg.child(0).as_int() == 42
    op = msg.child(1)
    assert op.tag == 0x6E
    assert op.child(0).value == b"dc=x"
    assert op.child(1).tag == 0x30
    assert [c.value for c in op.child(1).children] == [b"a", b"b"]

def test_decode_nested_zero_length():
    el = ber.decode(bytes.fromhex("30 00"))
    assert el.children == []

def test_truncated_raises():
    with pytest.raises(ber.BerError):
        ber.decode(bytes.fromhex("30 05 02 01 01"))
    with pytest.raises(ber.BerError):
        ber.decode(bytes.fromhex("30 81"))

def test_indefinite_rejected():
    with pytest.raises(ber.BerError):
        ber.decode(bytes.fromhex("30 80 00 00"))
