
from __future__ import annotations

GE_SUFFIX = ">"

def escape_ldap_filter_bytes(value: bytes) -> bytes:
    return b"".join(b"\\%02x" % b for b in value)

def inject_ge(attribute: str) -> str:
    return attribute + GE_SUFFIX

def compare_ge(attribute: str, candidate: bytes) -> "tuple[str, bytes]":
    return inject_ge(attribute), escape_ldap_filter_bytes(candidate)
