
import struct
import uuid

import pytest

from kdsextract import gkdi

GMSA_SD = gkdi.GMSA_SD

def guid_literal(time_low, time_mid, time_hi, clock_seq, node):
    raw = (
        struct.pack("<IHH", time_low & 0xFFFFFFFF, time_mid & 0xFFFF, time_hi & 0xFFFF)
        + struct.pack(">H", clock_seq & 0xFFFF)
        + (node & 0xFFFFFFFFFFFF).to_bytes(6, "big")
    )
    return uuid.UUID(bytes_le=raw)

def hx(s):
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))

VECTORS = [
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_l1_seed_key',
        guid_literal(0x89F70521, 0x9D66, 0x441F, 0xC314, 0x1B462F9B1052),
        "SHA512",
        (255, 24, -1),
        hx("a6ef87dbbbf86b6bbe55750b941f13ca99efe5185e2e2bded5b838d8a0e776470537e68cae45a7a0f4b1d6c9bf5494c3f879e172e326557cdbb6a56e8799a722"),
        hx("bd538a073490f3cf9451c933025de9b22c97eaddaffa94b379e2b919a4bed1475bc67f6a9175b139c69204c57d4300a0141ffe34d12ced84614593b1aa13af1c"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_l2_seed_key',
        guid_literal(0x1A3D6C30, 0xAA81, 0xCB7F, 0xD3FE, 0x80775D135DFE),
        "SHA512",
        (321, 0, 12),
        hx("dfd95be3153a0805c65694e7d284aace5ab0aa493350025eb8dbc6df0b4e9256fb4cbfbe6237ce3732694e2608760076b67082d39abd3c0fedba1b8873645064"),
        hx("bbbd9376cd16c247ed40f5912d1908218c08f0915bae02fe02cbfb3753bde406f9c553acd95143cf63906a0440e3cf237d2335ae4e4b9cd2d946a71351ebcb7b"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_both_seed_keys (next older L1)',
        guid_literal(0x09DE0B38, 0xC743, 0x7ABF, 0x44EA, 0x7A3C3E404314),
        "SHA512",
        (123, 20, -1),
        hx("d5912d0eb3bd60e1371b1e525dd83be7fc5baf77018b0dba6bd948b7a98ebe5af37674332506a46c52c108a62f2a3e89251ad1bde6d539004679c0658853bb68"),
        hx("b1f7c5896e7dc791d9c0aaf8ca7dbab8c172a4f8b873db488a3c4cbd0f559b1152ffba39d4aff2d9e8aada90b27a3c94a5af996f4b8f584a4f37ccab4d505d3d"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_both_seed_keys (L2)',
        guid_literal(0x09DE0B38, 0xC743, 0x7ABF, 0x44EA, 0x7A3C3E404314),
        "SHA512",
        (123, 21, 0),
        hx("d5912d0eb3bd60e1371b1e525dd83be7fc5baf77018b0dba6bd948b7a98ebe5af37674332506a46c52c108a62f2a3e89251ad1bde6d539004679c0658853bb68"),
        hx("133c9bbd20d9227aeb38dfcd3be6bcbfc5983ba37202088ff5c8a70511214506a69c195a8807cd844bcb955e9569c8e4d197759f28577cc126d15f16a7da4ee0"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_previous_l0_idx',
        guid_literal(0x27136E8F, 0xE093, 0x6FE3, 0xE57F, 0x1D915B102E1C),
        "SHA512",
        (100, 31, -1),
        hx("b41118c60a19cafa5ecf858d1a2a2216527b2daedf386e9d599e42a46add6c7dc93868619761c880ff3674a77c6e5fbf3434d130a9727bb2cd2a2557bdcfc752"),
        hx("935cbdc06198eb28fa44b8d8278f51072c4613999236585041ede8e72d02fe95e3454f046382cbc0a700779b79474dd7e080509d76302d2937407e96e3d3d022"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha1 (next older L1)',
        guid_literal(0x970ABAD6, 0xFE55, 0x073A, 0xCAF1, 0xB801D3F26BD3),
        "SHA1",
        (1, 1, -1),
        hx("3bed03bf0fb7d4013149154f24ca2d59b98db6d588cb1f54eca083855e25eb28d3562a01adc78c4b70e0b72a59515863e7732b853fba02dd7646e63108441211"),
        hx("576cb68f2e52eb739f817b488c3590d86f1c2c365f3fc9201d9c7fee7494853d58746ee13e48f18aa6fa69f7157de3d07de34e13836792b7c088ffb6914a89c2"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha1 (L2)',
        guid_literal(0x970ABAD6, 0xFE55, 0x073A, 0xCAF1, 0xB801D3F26BD3),
        "SHA1",
        (1, 2, 3),
        hx("3bed03bf0fb7d4013149154f24ca2d59b98db6d588cb1f54eca083855e25eb28d3562a01adc78c4b70e0b72a59515863e7732b853fba02dd7646e63108441211"),
        hx("3ffb825adaf116b6533207d568a30ed3d3f21c68840941c9456684f9afa11b056e0c59391b4d88c495d984c3d680029cc5c594630f34179119c1c5acaae5e90e"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha256 (next older L1)',
        guid_literal(0x45E26207, 0xED33, 0xDCD5, 0x925A, 0x518A0DEEF69E),
        "SHA256",
        (222, 21, -1),
        hx("28b5b6503d3c1d24814de781bb7bfce3ef69eed1ce4809372bee2c506270c5f0b5c6df597472623f256c86daa0991e8a11a1705f21b2cfdc0bb9db4ba23246a2"),
        hx("57aced6e75f83f3af4f879b38b60f090b42e4bfa022fae3e6fd94280b469b0ec15d8b853a870b5fbdf28708cce19273b74a573acbe0deda8ef515db4691e2dcb"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha256 (L2)',
        guid_literal(0x45E26207, 0xED33, 0xDCD5, 0x925A, 0x518A0DEEF69E),
        "SHA256",
        (222, 22, 22),
        hx("28b5b6503d3c1d24814de781bb7bfce3ef69eed1ce4809372bee2c506270c5f0b5c6df597472623f256c86daa0991e8a11a1705f21b2cfdc0bb9db4ba23246a2"),
        hx("752a0879ae2424c0504c7493599f13e588e1bbdc252f83325ad5b1fb91c24c8901d440f3ff9ffba59fcd65bb975732d9f383dd50b898174bb9393e383d25d540"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha384 (next older L1)',
        guid_literal(0x66E6D9F7, 0x4924, 0xF3FC, 0xFE34, 0x605634D42EBD),
        "SHA384",
        (287, 27, -1),
        hx("23e5ba86cbd88f7b432ee66dbb03bf4eebf401cbfc3df735d4d728b503c87f843207c6f6153f190dfe85a86cb8d8b74df13b25305981be8d7e29c96ee54c9630"),
        hx("fabadd7a9a63df57d6832df7a735aebb6e181888b2eaf301a2e4ff9a70246d38ab1d2416325bf3eb726a0267bab4bd950c7291f05ea5f17197ece56992af3eb8"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha384 (L2)',
        guid_literal(0x66E6D9F7, 0x4924, 0xF3FC, 0xFE34, 0x605634D42EBD),
        "SHA384",
        (287, 28, 27),
        hx("23e5ba86cbd88f7b432ee66dbb03bf4eebf401cbfc3df735d4d728b503c87f843207c6f6153f190dfe85a86cb8d8b74df13b25305981be8d7e29c96ee54c9630"),
        hx("ec1c65634b5694818e1d341da9996db8f2a1ef6a2c776a7126a7ebd18b37a073afdac44c41b167b14e4b872d485bbb6d7b70964215d0e84a2ff142a9d943f205"),
    ),
    (
        'samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_derive_key_exact',
        guid_literal(0xD95FB06F, 0x5A9C, 0x1829, 0xE20D, 0x27F3F2ECFBEB),
        "SHA512",
        (333, 22, 11),
        hx("489f3531c537774d432d6b97e3bc1f43d2e8c6dc17eb0e4fd9a0870d2f1ebf92e2496668a8b5bd11aea2d32d0aab716f48fe569f5c9b50ff3f9bf5deaea572fb"),
        hx("d6ab3b14f4f4c8908aa3464011b39f10a8bfadb9974af90f7d9a9fede2fdc6e5f68a628ec00f9994a3abd8a52ae9e2db4f68e83648311e9d7765f2535515b5e2"),
    ),
]

@pytest.mark.parametrize(
    "name,guid,hash_name,gkid,root_key_data,expected",
    VECTORS,
    ids=[v[0] for v in VECTORS],
)
def test_samba_seed_key_vectors(name, guid, hash_name, gkid, root_key_data, expected):
    got = gkdi.compute_seed_key(root_key_data, guid, gkid, hash_name)
    assert got == expected

def test_gkid_l1_31_skips_walk():

    name, guid, hash_name, gkid, root_key_data, expected = VECTORS[4]
    got = gkdi.compute_seed_key(root_key_data, guid, gkid, hash_name)
    assert got == expected

def test_invalid_gkids_rejected():
    guid = guid_literal(0x4CDF4285, 0xC46A, 0x62A3, 0x2F7D, 0x95F97342685B)
    data = bytes(64)
    for gkid in [(-1, -1, -1), (-2, -1, -1), (-1, 0, 0), (0, -1, 0), (0, -2, -1), (0, 0, -2), (123, 0, 32), (456, 32, 0)]:
        with pytest.raises(gkdi.GkdiError):
            gkdi.compute_seed_key(data, guid, gkid, "SHA512")
    with pytest.raises(gkdi.GkdiError):
        gkdi.compute_seed_key(bytes(32), guid, (0, 0, 0), "SHA512")

def test_derivation_ctx_layout():
    guid = uuid.UUID("4cdf4285-c46a-62a3-2f7d-95f97342685b")
    ctx = gkdi.derivation_ctx(guid, 255, -1, -1)
    assert len(ctx) == 28
    assert ctx == guid.bytes_le + struct.pack("<iii", 255, -1, -1)
    ctx_sd = gkdi.derivation_ctx(guid, 1, 2, 3, b"\x01\x02")
    assert ctx_sd == ctx[:16] + struct.pack("<iii", 1, 2, 3) + b"\x01\x02"

def test_gkdi_constants():
    assert len(gkdi.GMSA_SD) == 60
    assert gkdi.LABEL_KDS_SERVICE == b"K\x00D\x00S\x00 \x00s\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00"
    assert len(gkdi.LABEL_KDS_SERVICE) == 24
    assert gkdi.LABEL_GMSA_PASSWORD.endswith(b"\x00\x00")
    assert len(gkdi.LABEL_GMSA_PASSWORD) == 28

def test_gkid_from_nttime():

    t = 0
    assert gkdi.gkid_from_nttime(t) == (0, 0, 0)
    t = gkdi.KEY_CYCLE_DURATION
    assert gkdi.gkid_from_nttime(t) == (0, 0, 1)
    t = 32 * gkdi.KEY_CYCLE_DURATION
    assert gkdi.gkid_from_nttime(t) == (0, 1, 0)
    t = 32 * 32 * gkdi.KEY_CYCLE_DURATION
    assert gkdi.gkid_from_nttime(t) == (1, 0, 0)

def test_unix_to_nttime():
    assert gkdi.unix_to_nttime(0) == 116444736000000000

def test_parse_kdf_param():

    for name in gkdi.SUPPORTED_HASHES:
        chars = name.encode("utf-16-le")
        blob = struct.pack("<4I", 0, 1, len(chars), 0) + chars + b"\x00\x00"
        assert gkdi.parse_kdf_param(blob) == name
    assert gkdi.parse_kdf_param(None) == "SHA256"
    with pytest.raises(gkdi.GkdiError):
        gkdi.parse_kdf_param(struct.pack("<4I", 0, 1, 8, 0) + "md5".encode("utf-16-le") + b"\x00\x00")
    with pytest.raises(gkdi.GkdiError):
        gkdi.parse_kdf_param(b"\x00" * 8)
