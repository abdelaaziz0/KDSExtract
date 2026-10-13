
from __future__ import annotations

import hashlib
import hmac as _hmac
import struct
import uuid as _uuid
from typing import Optional, Tuple

KEY_LEN = 64
L1_KEY_ITERATION = 32
L2_KEY_ITERATION = 32
KEY_CYCLE_DURATION = 360000000000
MAX_CLOCK_SKEW = 3000000000
PASSWORD_LEN = 256

GMSA_SD = bytes(
    [
        0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x9F, 0x01, 0x12, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    ]
)

LABEL_KDS_SERVICE = "KDS service".encode("utf-16-le") + b"\x00\x00"
LABEL_GMSA_PASSWORD = "GMSA PASSWORD".encode("utf-16-le") + b"\x00\x00"

SUPPORTED_HASHES = ("SHA1", "SHA256", "SHA384", "SHA512")
DEFAULT_HASH = "SHA256"
SAMBA_CREATION_DEFAULT = "SHA512"
KDF_ALGORITHM_ID = "SP800_108_CTR_HMAC"

class GkdiError(ValueError):
    pass

def sp800_108_ctr_hmac(
    key: bytes, label: bytes, context: bytes, hash_name: str, out_len: int
) -> bytes:
    digest_len = hashlib.new(hash_name).digest_size
    L = out_len * 8
    out = bytearray()
    i = 1
    while len(out) < out_len:
        msg = (
            struct.pack(">I", i)
            + label
            + b"\x00"
            + context
            + struct.pack(">I", L)
        )
        out += _hmac.new(key, msg, hash_name).digest()
        i += 1
    return bytes(out[:out_len])

def derivation_ctx(
    root_key_id: _uuid.UUID, l0: int, l1: int, l2: int, sd: bytes = b""
) -> bytes:
    if sd is None:
        sd = b""
    return root_key_id.bytes_le + struct.pack("<iii", l0, l1, l2) + sd

def _validate_gkid(l0: int, l1: int, l2: int) -> None:
    if not (-1 <= l1 < L1_KEY_ITERATION and -1 <= l2 < L2_KEY_ITERATION):
        raise GkdiError(f"invalid GKID ({l0}, {l1}, {l2})")
    if l1 == -1 and l2 != -1:
        raise GkdiError(f"invalid GKID ({l0}, {l1}, {l2})")

def compute_seed_key(
    root_key_data: bytes,
    root_key_id: _uuid.UUID,
    gkid: Tuple[int, int, int],
    hash_name: str,
    sd: bytes = GMSA_SD,
) -> bytes:
    l0, l1, l2 = gkid
    _validate_gkid(l0, l1, l2)
    if l0 < 0 or l1 < 0:

        raise GkdiError(f"invalid GKID ({l0}, {l1}, {l2})")
    if len(root_key_data) != KEY_LEN:
        raise GkdiError(f"root key data must be {KEY_LEN} bytes")

    key = sp800_108_ctr_hmac(
        root_key_data,
        LABEL_KDS_SERVICE,
        derivation_ctx(root_key_id, l0, -1, -1),
        hash_name,
        KEY_LEN,
    )

    key = sp800_108_ctr_hmac(
        key,
        LABEL_KDS_SERVICE,
        derivation_ctx(root_key_id, l0, 31, -1, sd),
        hash_name,
        KEY_LEN,
    )

    for n in range(30, l1 - 1, -1):
        key = sp800_108_ctr_hmac(
            key,
            LABEL_KDS_SERVICE,
            derivation_ctx(root_key_id, l0, n, -1),
            hash_name,
            KEY_LEN,
        )

    if l2 >= 0:

        for n in range(31, l2 - 1, -1):
            key = sp800_108_ctr_hmac(
                key,
                LABEL_KDS_SERVICE,
                derivation_ctx(root_key_id, l0, l1, n),
                hash_name,
                KEY_LEN,
            )
    return key

def gkid_from_nttime(nttime: int) -> Tuple[int, int, int]:
    l0 = nttime // (L1_KEY_ITERATION * L2_KEY_ITERATION * KEY_CYCLE_DURATION)
    l1 = (
        nttime // (L2_KEY_ITERATION * KEY_CYCLE_DURATION) % L1_KEY_ITERATION
    )
    l2 = nttime // KEY_CYCLE_DURATION % L2_KEY_ITERATION
    return int(l0), int(l1), int(l2)

def unix_to_nttime(unix_seconds: float) -> int:
    return int(unix_seconds * 10_000_000) + 116444736000000000

def sid_to_binary(sid: str) -> bytes:
    parts = sid.split("-")
    if len(parts) < 3 or parts[0] != "S" or parts[1] != "1":
        raise GkdiError(f"not a SID: {sid!r}")
    authority = int(parts[2])
    subauths = [int(p) for p in parts[3:]]
    if authority > 0xFFFFFFFFFFFF:
        raise GkdiError("SID authority too large")
    if len(subauths) > 15:
        raise GkdiError("SID has too many subauthorities")
    out = bytearray()
    out.append(1)
    out.append(len(subauths))
    out += authority.to_bytes(6, "big")
    for s in subauths:
        out += struct.pack("<I", s)
    return bytes(out)

def gmsa_password(seed_key: bytes, sid: str, hash_name: str) -> bytes:
    sid_bin = sid_to_binary(sid)
    password = bytearray(
        sp800_108_ctr_hmac(
            seed_key, LABEL_GMSA_PASSWORD, sid_bin, hash_name, PASSWORD_LEN
        )
    )

    for n in range(0, PASSWORD_LEN, 2):
        if password[n] == 0 and password[n + 1] == 0:
            password[n] = 1
    return bytes(password)

def derive_gmsa_password(
    root_key_data: bytes,
    root_key_id: _uuid.UUID,
    gkid: Tuple[int, int, int],
    sid: str,
    hash_name: str,
) -> bytes:
    seed = compute_seed_key(root_key_data, root_key_id, gkid, hash_name)
    return gmsa_password(seed, sid, hash_name)

def parse_kdf_param(blob: Optional[bytes]) -> str:
    if blob is None:
        return DEFAULT_HASH
    if len(blob) < 16:
        raise GkdiError("KDFParam blob too short")
    hash_len = struct.unpack_from("<I", blob, 8)[0]
    if 16 + hash_len > len(blob):
        raise GkdiError("KDFParam blob truncated")
    name = blob[16 : 16 + hash_len].decode("utf-16-le")
    if name not in SUPPORTED_HASHES:
        raise GkdiError(f"unsupported KDF hash algorithm {name!r}")
    return name

def _lrot(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def md4(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def hh(x, y, z):
        return x ^ y ^ z

    data = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += bit_len.to_bytes(8, "little")

    round1 = [3, 7, 11, 19]
    round2 = [3, 5, 9, 13]
    round3 = [3, 9, 11, 15]

    for off in range(0, len(data), 64):
        x = struct.unpack_from("<16I", data, off)
        a, b, c, d = h
        for i in range(16):
            k = i
            a = _lrot((a + f(b, c, d) + x[k]) & 0xFFFFFFFF, round1[i % 4])
            a, b, c, d = d, a, b, c
        for i in range(16):
            k = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15][i]
            a = _lrot(
                (a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF,
                round2[i % 4],
            )
            a, b, c, d = d, a, b, c
        for i in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i]
            a = _lrot(
                (a + hh(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF,
                round3[i % 4],
            )
            a, b, c, d = d, a, b, c
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF

    return struct.pack("<4I", *h)

def nt_hash(password_utf16le: bytes) -> bytes:
    return md4(password_utf16le)
