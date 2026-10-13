import struct
import uuid

import pytest

from kdsextract import gkdi
from kdsextract.gmsa import GmsaAccount, ManagedPasswordId, derive_password_for_account

def make_managed_password_id(
    root_key_guid=uuid.UUID("12345678-1234-1234-1234-123456789abc"),
    l0=5,
    l1=6,
    l2=7,
    domain="lab.local",
    forest="lab.local",
    info=b"\xaa\xbb",
):
    dom = domain.encode("utf-16-le") + b"\x00\x00"
    forest_b = forest.encode("utf-16-le") + b"\x00\x00"
    blob = (
        struct.pack("<6I", 1, 0x4B53444B, 0, l0, l1, l2)
        + root_key_guid.bytes_le
        + struct.pack("<3I", len(info), len(dom), len(forest_b))
        + info
        + dom
        + forest_b
    )
    return ManagedPasswordId.from_blob(blob)

def test_managed_password_id_parse():
    guid = uuid.UUID("12345678-1234-1234-1234-123456789abc")
    mp = make_managed_password_id(root_key_guid=guid, l0=5, l1=6, l2=7)
    assert mp.version == 1
    assert mp.root_key_id == guid
    assert mp.gkid == (5, 6, 7)
    assert mp.domain_name == "lab.local"
    assert mp.forest_name == "lab.local"
    assert mp.additional_info == b"\xaa\xbb"

def test_managed_password_id_bad_magic():
    bad = bytearray(make_managed_password_id().raw)
    bad[4:8] = b"XXXX"
    with pytest.raises(ValueError):
        ManagedPasswordId.from_blob(bytes(bad))

def test_managed_password_id_truncated():
    blob = make_managed_password_id().raw
    with pytest.raises(ValueError):
        ManagedPasswordId.from_blob(blob[:-4])

def test_derive_password_for_account():
    mp = make_managed_password_id(l0=5, l1=6, l2=7)
    account = GmsaAccount(name="svc$", dn="CN=svc,CN=Computations,DC=lab,DC=local", sid="S-1-5-21-1-2-3-1106", managed_password_id=mp)
    root_key_data = bytes(range(64))
    pw = derive_password_for_account(account, root_key_data, "SHA512")
    assert len(pw) == 256

    for n in range(0, 256, 2):
        assert pw[n : n + 2] != b"\x00\x00"

    assert derive_password_for_account(account, root_key_data, "SHA512") == pw

    other = GmsaAccount(name="svc2$", dn="x", sid="S-1-5-21-1-2-3-1107", managed_password_id=mp)
    assert derive_password_for_account(other, root_key_data, "SHA512") != pw

def test_sid_to_binary():
    assert gkdi.sid_to_binary("S-1-5-10") == bytes.fromhex("01 01 00 00 00 00 00 05 0a 00 00 00")
    assert gkdi.sid_to_binary("S-1-5-21-100-200-300-1106") == (
        bytes([1, 5]) + bytes.fromhex("00 00 00 00 00 05")
        + struct.pack("<5I", 21, 100, 200, 300, 1106)
    )

    from kdsextract.discover import sid_from_binary
    assert sid_from_binary(gkdi.sid_to_binary("S-1-5-21-100-200-300-1106")) == "S-1-5-21-100-200-300-1106"
    with pytest.raises(gkdi.GkdiError):
        gkdi.sid_to_binary("O-1-5")
    with pytest.raises(gkdi.GkdiError):
        gkdi.sid_to_binary("S-1-5-" + "-".join(["1"] * 16))

def test_md4_nt_hash():

    assert gkdi.md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert gkdi.md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert gkdi.md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert gkdi.md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"
    assert gkdi.md4(b"abcdefghijklmnopqrstuvwxyz").hex() == "d79e1c308aa5bbcdeea8ed63df412da9"
    assert gkdi.md4(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    ).hex() == "043f8582f241db351ce627e153e7f0e4"
    assert gkdi.md4(
        b"1234567890" * 8
    ).hex() == "e33b4ddc9c38f2199c3e7b164fcc0536"

    assert gkdi.nt_hash("".encode("utf-16-le")).hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert gkdi.nt_hash("password".encode("utf-16-le")).hex() == "8846f7eaee8fb117ad06bdd830b7586c"
    assert gkdi.nt_hash("Password".encode("utf-16-le")).hex() == "a4f49c406510bdcab6824ee7c30fd852"
    assert gkdi.nt_hash("Password1!".encode("utf-16-le")).hex() == "7facdc498ed1680c4fd1448319a8c04f"

def test_gmsa_password_postprocess():

    buf = bytearray(b"\x00" * 256)
    for n in range(0, 256, 2):
        if buf[n] == 0 and buf[n + 1] == 0:
            buf[n] = 1
    assert b"\x00\x00" not in bytes(buf)
