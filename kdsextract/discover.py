
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

from . import gkdi, ldap
from .gmsa import GmsaAccount, ManagedPasswordId

KDS_ROOT_KEY_CONTAINER = (
    "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services"
)

ROOT_KEY_ATTRS = [
    "cn",
    "msKds-CreateTime",
    "msKds-UseStartTime",
    "msKds-Version",
    "msKds-KDFAlgorithmID",
    "msKds-KDFParam",
    "msKds-DomainID",
]

GMSA_ATTRS = [
    "cn",
    "sAMAccountName",
    "objectSid",
    "msDS-ManagedPasswordID",
    "msDS-GroupMSAMembership",
]

class DiscoveryError(Exception):
    pass

def sid_from_binary(blob: bytes) -> str:
    rev = blob[0]
    count = blob[1]
    authority = int.from_bytes(blob[2:8], "big")
    subs = [int.from_bytes(blob[8 + 4 * i : 12 + 4 * i], "little") for i in range(count)]
    return "S-" + "-".join(str(x) for x in [rev, authority] + subs)

def get_root_dse(client: ldap.LdapClient) -> Dict[str, List[bytes]]:
    return {
        e.dn: e.attrs
        for e in client.search(
            "", ldap.filter_present("objectClass"), ldap.SCOPE_BASE, ["*"]
        )
    }.get("", {})

class NamingContexts:
    def __init__(self, root_dse: Dict[str, List[bytes]]) -> None:
        def one(attr: str) -> str:
            vals = [
                v.decode()
                for k, vs in root_dse.items()
                if k.lower() == attr.lower()
                for v in vs
            ]
            return vals[0] if vals else ""

        self.default: str = one("defaultNamingContext")
        self.configuration: str = one("configurationNamingContext")
        self.root_domain: str = one("rootDomainNamingContext")

    @classmethod
    def from_client(cls, client: ldap.LdapClient) -> "NamingContexts":
        return cls(get_root_dse(client))

@dataclass
class KdsRootKey:
    guid: uuid.UUID
    dn: str
    create_time: int
    use_start_time: int
    version: int
    kdf_algorithm_id: str
    kdf_param: Optional[bytes]

    def hash_name(self) -> str:
        if self.kdf_algorithm_id != gkdi.KDF_ALGORITHM_ID:
            raise DiscoveryError(
                f"unsupported KDF algorithm {self.kdf_algorithm_id!r} on root key {self.guid}"
            )
        return gkdi.parse_kdf_param(self.kdf_param)

def _first_str(entry, attr: str) -> str:
    v = entry.first(attr)
    return v.decode("utf-8", "replace") if v is not None else ""

def list_kds_root_keys(
    client: ldap.LdapClient, ncs: Optional[NamingContexts] = None
) -> List[KdsRootKey]:
    if ncs is None:
        ncs = NamingContexts.from_client(client)
    base = f"{KDS_ROOT_KEY_CONTAINER},{ncs.configuration}"
    entries = client.search(
        base,
        ldap.filter_eq("objectClass", b"msKds-ProvRootKey"),
        ldap.SCOPE_ONE,
        ROOT_KEY_ATTRS,
    )
    keys: List[KdsRootKey] = []
    for e in entries:
        try:
            guid = uuid.UUID(_first_str(e, "cn"))
        except ValueError as exc:
            continue
        keys.append(
            KdsRootKey(
                guid=guid,
                dn=e.dn,
                create_time=int(_first_str(e, "msKds-CreateTime") or 0),
                use_start_time=int(_first_str(e, "msKds-UseStartTime") or 0),
                version=int(_first_str(e, "msKds-Version") or 0),
                kdf_algorithm_id=_first_str(e, "msKds-KDFAlgorithmID"),
                kdf_param=e.first("msKds-KDFParam"),
            )
        )
    keys.sort(key=lambda k: k.create_time, reverse=True)
    return keys

def list_gmsa_accounts(
    client: ldap.LdapClient, ncs: Optional[NamingContexts] = None
) -> List[GmsaAccount]:
    if ncs is None:
        ncs = NamingContexts.from_client(client)
    entries = client.search(
        ncs.default,
        ldap.filter_eq("objectClass", b"msDS-GroupManagedServiceAccount"),
        ldap.SCOPE_SUB,
        GMSA_ATTRS,
    )
    accounts: List[GmsaAccount] = []
    for e in entries:
        name = _first_str(e, "sAMAccountName") or _first_str(e, "cn")
        sid_blob = e.first("objectSid")
        sid = sid_from_binary(sid_blob) if sid_blob else ""
        mp_blob = e.first("msDS-ManagedPasswordID")
        mp = None
        if mp_blob is not None:
            try:
                mp = ManagedPasswordId.from_blob(mp_blob)
            except ValueError as exc:
                raise DiscoveryError(
                    f"failed to parse msDS-ManagedPasswordID of {name}: {exc}"
                ) from exc
        accounts.append(GmsaAccount(name=name, dn=e.dn, sid=sid, managed_password_id=mp))
    return accounts

def find_root_key(keys: List[KdsRootKey], guid: uuid.UUID) -> Optional[KdsRootKey]:
    for k in keys:
        if k.guid == guid:
            return k
    return None

def kds_root_key_dn(ncs: NamingContexts, guid) -> str:
    return f"CN={guid},{KDS_ROOT_KEY_CONTAINER},{ncs.configuration}"

def root_key_hash_candidates(entry_attrs: Optional[dict]) -> List[str]:
    if entry_attrs:
        algo = entry_attrs.get("msKds-KDFAlgorithmID")
        if algo and algo != b"SP800_108_CTR_HMAC":
            raise DiscoveryError(f"unsupported KDF algorithm {algo!r}")
        kdf_param = entry_attrs.get("msKds-KDFParam")
        if kdf_param:
            return [gkdi.parse_kdf_param(kdf_param[0])]
    return [gkdi.SAMBA_CREATION_DEFAULT, gkdi.DEFAULT_HASH]

def nttime_now() -> int:
    return gkdi.unix_to_nttime(time.time())
