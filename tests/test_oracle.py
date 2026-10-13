import os
import random

import pytest

from kdsextract import inject
from kdsextract.oracle import CompareOracle, OracleError

class MockLdap:

    def __init__(self, stored: bytes, reject_injection: bool = False):
        self.stored = stored
        self.reject_injection = reject_injection
        self.queries = 0
        self.last_attr = None
        self.last_value = None

    def compare(self, dn, attribute, value):
        self.queries += 1
        self.last_attr = attribute
        self.last_value = value
        if self.reject_injection:
            return 21
        assert attribute.endswith(">"), "oracle must inject the operator"
        assert b"\x00" not in value
        for ch in b"()*=\x00":
            assert bytes([ch]) not in value, "candidates must be fully escaped"

        raw = bytes(int(value[i : i + 3][1:], 16) for i in range(0, len(value), 3))

        n = min(len(self.stored), len(raw))
        a, b = self.stored[:n], raw[:n]
        if a == b:
            ge = len(self.stored) >= len(raw)
        else:
            ge = a > b
        return 6 if ge else 5

def mock_ldap(value, **kw):
    return MockLdap(value, **kw)

def test_ge_semantics():
    o = CompareOracle(mock_ldap(bytes.fromhex("00ff10")), "dn", "msKds-RootKeyData")
    assert o.ge(b"\x00") is True
    assert o.ge(b"\x00\xff") is True
    assert o.ge(b"\x00\xff\x11") is False
    assert o.ge(b"\x00\xff\x10") is True
    assert o.queries == 4

def test_recover_known_length():
    random.seed(1234)
    for trial in range(50):
        stored = bytes(random.randrange(256) for _ in range(random.choice([1, 8, 64, 128])))
        mock = mock_ldap(stored)
        o = CompareOracle(mock, "dn", "attr")
        got = o.recover(length=len(stored))
        assert got == stored, f"trial {trial}"
        assert o.queries <= len(stored) * 9

def test_recover_discovers_length():
    random.seed(99)
    for trial in range(50):
        stored = bytes(random.randrange(256) for _ in range(random.randrange(0, 40)))
        mock = mock_ldap(stored)
        o = CompareOracle(mock, "dn", "attr")
        got = o.recover()
        assert got == stored, f"trial {trial}"

def test_recover_with_nul_bytes():
    stored = b"\x00\x00\xff\x00\x01\x00" + bytes(10)
    o = CompareOracle(mock_ldap(stored), "dn", "attr")
    assert o.recover(length=len(stored)) == stored

def test_recover_over_length_returns_zero_padding():

    o = CompareOracle(mock_ldap(b"ab"), "dn", "attr")
    got = o.recover(length=4)
    assert got == b"ab\x00\x00"

def test_rejected_injection_raises():

    o = CompareOracle(mock_ldap(b"ab", reject_injection=True), "dn", "attr")
    with pytest.raises(OracleError):
        o.recover(length=2)

def test_query_cost():
    stored = bytes([0x80] * 64)
    o = CompareOracle(mock_ldap(stored), "dn", "attr")
    o.recover(length=64)

    assert 64 <= o.queries <= 64 * 9

def test_query_cost_zero_bytes():
    stored = bytes(64)
    o = CompareOracle(mock_ldap(stored), "dn", "attr")
    o.recover(length=64)

    assert o.queries == 64
