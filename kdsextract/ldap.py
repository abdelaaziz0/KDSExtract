
from __future__ import annotations

import socket
import ssl
from typing import Dict, List, Optional, Sequence, Tuple

from . import ber

TAG_BIND_REQUEST = 0x60
TAG_BIND_RESPONSE = 0x61
TAG_UNBIND_REQUEST = 0x42
TAG_SEARCH_REQUEST = 0x63
TAG_SEARCH_ENTRY = 0x64
TAG_SEARCH_DONE = 0x65
TAG_COMPARE_REQUEST = 0x6E
TAG_COMPARE_RESPONSE = 0x6F
TAG_EXTENDED_REQUEST = 0x77
TAG_EXTENDED_RESPONSE = 0x78
TAG_SEARCH_REFERENCE = 0x73

OID_STARTTLS = b"1.3.6.5.1"

SCOPE_BASE = 0
SCOPE_ONE = 1
SCOPE_SUB = 2

RES_COMPARE_FALSE = 5
RES_COMPARE_TRUE = 6

RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    5: "compareFalse",
    6: "compareTrue",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    10: "referral",
    11: "adminLimitExceeded",
    14: "saslBindInProgress",
    16: "noSuchAttribute",
    17: "undefinedAttributeType",
    18: "inappropriateMatching",
    19: "constraintViolation",
    20: "attributeOrValueExists",
    21: "invalidAttributeSyntax",
    32: "noSuchObject",
    34: "invalidDNSyntax",
    36: "aliasDereferencingProblem",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    52: "unavailable",
    53: "unwillingToPerform",
    64: "namingViolation",
    65: "objectClassViolation",
    69: "objectClassModsProhibited",
    71: "affectsMultipleDSAs",
    80: "other",
}

class LdapError(Exception):
    def __init__(self, code: int, message: str, matched_dn: str = "") -> None:
        self.code = code
        self.matched_dn = matched_dn
        name = RESULT_CODES.get(code, f"code {code}")
        super().__init__(f"LDAP {name} ({code}): {message}")

def filter_eq(attr: str, value: bytes) -> bytes:
    return ber.context(3, ber.octet_string(attr.encode()), ber.octet_string(value))

def filter_present(attr: str) -> bytes:
    return ber.context(7, attr.encode(), constructed=False)

def filter_and(*parts: bytes) -> bytes:
    return ber.context(0, *parts)

def filter_or(*parts: bytes) -> bytes:
    return ber.context(1, *parts)

class _Entry:
    __slots__ = ("dn", "attrs")

    def __init__(self, dn: str, attrs: Dict[str, List[bytes]]) -> None:
        self.dn = dn
        self.attrs = attrs

    def get(self, attr: str) -> List[bytes]:

        for k, v in self.attrs.items():
            if k.lower() == attr.lower():
                return v
        return []

    def first(self, attr: str) -> Optional[bytes]:
        vals = self.get(attr)
        return vals[0] if vals else None

class LdapClient:

    def __init__(
        self,
        host: str,
        port: int = 389,
        timeout: float = 10.0,
        use_ssl: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ssl = use_ssl
        self._sock: Optional[socket.socket] = None
        self._buf = b""
        self._msgid = 0

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        if self.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._send(self._next_id(), ber.tlv(TAG_UNBIND_REQUEST, b""))
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "LdapClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _next_id(self) -> int:
        self._msgid += 1
        return self._msgid

    def _send(self, msgid: int, op: bytes) -> None:
        assert self._sock is not None
        msg = ber.sequence(ber.integer(msgid), op)
        self._sock.sendall(msg)

    def _recv_exact(self, want: int) -> bytes:
        assert self._sock is not None
        while len(self._buf) < want:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise LdapError(80, "connection closed by server")
            self._buf += chunk
        out, self._buf = self._buf[:want], self._buf[want:]
        return out

    def _read_message(self) -> Tuple[int, ber.Tlv]:
        assert self._sock is not None

        while True:
            try:
                outer_tag, _, outer_end = ber.read_tlv(self._buf, 0)
                break
            except ber.BerError:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise LdapError(80, "connection closed by server")
                self._buf += chunk

        need = outer_end
        while len(self._buf) < need:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise LdapError(80, "connection closed by server")
            self._buf += chunk
        raw = self._recv_exact(need)
        msg = ber.decode(raw)
        msgid = msg.child(0).as_int()
        op = msg.child(1)
        return msgid, op

    def _read_response(self, want_msgid: int) -> ber.Tlv:
        while True:
            msgid, op = self._read_message()
            if msgid == 0:
                continue
            _expect_msgid(msgid, want_msgid)
            return op

    def bind(self, principal: str, password: str) -> None:
        req = ber.application(
            0,
            ber.integer(3),
            ber.octet_string(principal.encode()),
            ber.context(0, password.encode(), constructed=False),
        )
        self._send(self._next_id(), req)
        op = self._read_response(self._msgid)
        if op.tag != TAG_BIND_RESPONSE:
            raise LdapError(2, f"unexpected response tag 0x{op.tag:02x} for bind")
        self._check_result(op, "bind")

    def _check_result(self, op: ber.Tlv, what: str) -> int:
        code = op.child(0).as_int()
        matched_dn = op.child(1).value.decode("utf-8", "replace") if len(op.children or []) > 1 else ""
        msg = op.child(2).value.decode("utf-8", "replace") if len(op.children or []) > 2 else ""
        if code != 0:
            raise LdapError(code, f"{what}: {msg or 'no diagnostic'}", matched_dn)
        return code

    def search(
        self,
        base: str,
        filt: bytes,
        scope: int = SCOPE_SUB,
        attrs: Sequence[str] = (),
        time_limit: int = 30,
    ) -> List[_Entry]:
        req = ber.application(
            3,
            ber.octet_string(base.encode()),
            ber.enumerated(scope),
            ber.enumerated(0),
            ber.integer(0),
            ber.integer(time_limit),
            ber.boolean(False),
            filt,
            ber.sequence(*[ber.octet_string(a.encode()) for a in attrs]),
        )
        self._send(self._next_id(), req)
        entries: List[_Entry] = []
        while True:
            op = self._read_response(self._msgid)
            if op.tag == TAG_SEARCH_ENTRY:
                dn = op.child(0).value.decode("utf-8", "replace")
                attrs_el = op.child(1)
                out: Dict[str, List[bytes]] = {}
                for pa in attrs_el.children or []:
                    name = pa.child(0).value.decode("utf-8", "replace")
                    values: List[bytes] = []
                    if len(pa.children or []) > 1:
                        for v in pa.child(1).children or []:
                            values.append(v.value)
                    out.setdefault(name, []).extend(values)
                entries.append(_Entry(dn, out))
            elif op.tag == TAG_SEARCH_REFERENCE:
                continue
            elif op.tag == TAG_SEARCH_DONE:
                self._check_result(op, "search")
                return entries
            else:
                raise LdapError(2, f"unexpected response tag 0x{op.tag:02x} during search")

    def starttls(self) -> None:
        assert self._sock is not None
        if self._buf:
            raise LdapError(2, "starttls with pending buffered messages")
        req = ber.application(23, ber.context(0, OID_STARTTLS, constructed=False))
        self._send(self._next_id(), req)
        op = self._read_response(self._msgid)
        if op.tag != TAG_EXTENDED_RESPONSE:
            raise LdapError(2, f"unexpected response tag 0x{op.tag:02x} for starttls")
        code = op.child(0).as_int()
        if code != 0:
            msg = op.child(2).value.decode("utf-8", "replace") if len(op.children or []) > 2 else ""
            raise LdapError(code, f"starttls: {msg or 'rejected'}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._sock = ctx.wrap_socket(self._sock)

    def compare(self, dn: str, attribute: str, value: bytes) -> int:
        ava = ber.sequence(
            ber.octet_string(attribute.encode()),
            ber.octet_string(value),
        )
        req = ber.application(14, ber.octet_string(dn.encode()), ava)
        self._send(self._next_id(), req)
        op = self._read_response(self._msgid)
        if op.tag != TAG_COMPARE_RESPONSE:
            raise LdapError(2, f"unexpected response tag 0x{op.tag:02x} for compare")
        code = op.child(0).as_int()
        msg = op.child(2).value.decode("utf-8", "replace") if len(op.children or []) > 2 else ""
        if code not in (RES_COMPARE_TRUE, RES_COMPARE_FALSE) and code != 0:

            name = RESULT_CODES.get(code, f"code {code}")
            raise LdapError(code, f"compare: {msg or name}")
        return code

def _expect_msgid(got: int, want: int) -> None:
    if got != want:
        raise LdapError(2, f"message id mismatch: got {got}, expected {want}")
