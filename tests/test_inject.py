import pytest

from kdsextract import inject
from kdsextract.ldap import filter_eq, filter_present

def test_escape_all_bytes():
    assert inject.escape_ldap_filter_bytes(b"") == b""
    assert inject.escape_ldap_filter_bytes(b"\x00") == b"\\00"
    assert inject.escape_ldap_filter_bytes(b"\x41\x2a\x28\x00\xff") == (
        b"\\41\\2a\\28\\00\\ff"
    )

def test_inject_ge():
    assert inject.inject_ge("msKds-RootKeyData") == "msKds-RootKeyData>"
    attr, value = inject.compare_ge("msKds-RootKeyData", b"\x00\x7f")

    assert attr == "msKds-RootKeyData>"
    assert value == b"\\00\\7f"

    assert b"\x00" not in value
    for ch in b"()*=\x00":
        assert bytes([ch]) not in value

    assert all(c in b"0123456789abcdef\\" for c in value)

def test_search_filter_ber():
    f = filter_eq("objectClass", b"msKds-ProvRootKey")
    assert f[0] == 0xA3
    el = __import__("kdsextract.ber", fromlist=["decode"]).decode(f)
    assert el.child(0).value == b"objectClass"
    assert el.child(1).value == b"msKds-ProvRootKey"
    p = filter_present("objectClass")
    assert p == bytes.fromhex("87 0b 6f 62 6a 65 63 74 43 6c 61 73 73")
