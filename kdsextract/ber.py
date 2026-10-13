
from __future__ import annotations

import struct
from typing import Iterator, List, Optional, Tuple

class BerError(ValueError):
    pass

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out

def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value

def integer(value: int, tag: int = 0x02) -> bytes:
    out = b""
    if value == 0:
        out = b"\x00"
    else:

        pad = 0
        if value > 0 and value > 0x7F:
            pad = 0x00
        length = (value.bit_length() + 8) // 8 if value > 0 else ((-value).bit_length() + 8) // 8
        out = value.to_bytes(length, "big", signed=True)
        if value > 0 and out[0] > 0x7F:
            out = b"\x00" + out
    return tlv(tag, out)

def enumerated(value: int) -> bytes:
    return integer(value, tag=0x0A)

def boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")

def octet_string(value: bytes, tag: int = 0x04) -> bytes:
    return tlv(tag, value)

def sequence(*parts: bytes, tag: int = 0x30) -> bytes:
    return tlv(tag, b"".join(parts))

def application(app: int, *parts: bytes, constructed: bool = True) -> bytes:
    tag = 0x40 | app
    if constructed:
        tag |= 0x20
    return tlv(tag, b"".join(parts))

def context(ctx: int, *parts: bytes, constructed: bool = True) -> bytes:
    tag = 0x80 | ctx
    if constructed:
        tag |= 0x20
    return tlv(tag, b"".join(parts))

def parse_len(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data):
        raise BerError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    if first == 0x80:
        raise BerError("indefinite lengths not supported")
    nbytes = first & 0x7F
    if nbytes > 4:
        raise BerError("length too large")
    if pos + nbytes > len(data):
        raise BerError("truncated length")
    length = int.from_bytes(data[pos : pos + nbytes], "big")
    return length, pos + nbytes

class Tlv:

    __slots__ = ("tag", "value", "children")

    def __init__(self, tag: int, value: bytes) -> None:
        self.tag = tag
        self.value = value
        self.children: Optional[List["Tlv"]] = None
        if tag & 0x20:
            self.children = list(self._parse_children(value))

    @staticmethod
    def _parse_children(value: bytes) -> Iterator["Tlv"]:
        pos = 0
        while pos < len(value):
            tag, content, pos = read_tlv(value, pos)
            yield Tlv(tag, content)

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def child(self, index: int) -> "Tlv":
        if self.children is None or index >= len(self.children):
            raise BerError(f"element has no child {index}")
        return self.children[index]

    def as_int(self) -> int:
        return int.from_bytes(self.value, "big", signed=True)

    def __repr__(self) -> str:
        return f"Tlv(tag=0x{self.tag:02x}, len={len(self.value)})"

def read_tlv(data: bytes, pos: int = 0) -> Tuple[int, bytes, int]:
    if pos + 2 > len(data) + 1 or pos >= len(data):
        raise BerError("truncated element")
    tag = data[pos]
    pos += 1
    length, pos = parse_len(data, pos)
    if pos + length > len(data):
        raise BerError("truncated element content")
    return tag, data[pos : pos + length], pos + length

def decode(data: bytes) -> Tlv:
    tag, content, end = read_tlv(data, 0)
    if end != len(data):
        raise BerError("trailing bytes after element")
    return Tlv(tag, content)
