
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from typing import Optional

from . import gkdi

KEY_ENVELOPE_MAGIC = 0x4B53444B

class ManagedPasswordIdError(ValueError):
    pass

@dataclass
class ManagedPasswordId:
    version: int
    flags: int
    l0_index: int
    l1_index: int
    l2_index: int
    root_key_id: uuid.UUID
    additional_info: bytes = field(repr=False)
    domain_name: str
    forest_name: str
    raw: bytes = field(repr=False)

    @property
    def gkid(self) -> "tuple[int, int, int]":
        return (self.l0_index, self.l1_index, self.l2_index)

    @classmethod
    def from_blob(cls, blob: bytes) -> "ManagedPasswordId":
        if len(blob) < 52:
            raise ManagedPasswordIdError("ManagedPasswordID blob too short")
        version, magic, flags, l0, l1, l2 = struct.unpack_from("<6I", blob, 0)
        if magic != KEY_ENVELOPE_MAGIC:
            raise ManagedPasswordIdError(
                f"bad ManagedPasswordID magic 0x{magic:08x} (expected 'KDSK')"
            )
        root_key_id = uuid.UUID(bytes_le=blob[24:40])
        ai_len, dom_len, forest_len = struct.unpack_from("<3I", blob, 40)
        pos = 52
        if pos + ai_len > len(blob):
            raise ManagedPasswordIdError("ManagedPasswordID blob truncated (info)")
        additional_info = blob[pos : pos + ai_len]
        pos += ai_len

        if pos + dom_len > len(blob):
            raise ManagedPasswordIdError("ManagedPasswordID blob truncated (domain)")
        domain_name = blob[pos : pos + dom_len].decode("utf-16-le").rstrip("\x00")
        pos += dom_len
        if pos + forest_len > len(blob):
            raise ManagedPasswordIdError("ManagedPasswordID blob truncated (forest)")
        forest_name = blob[pos : pos + forest_len].decode("utf-16-le").rstrip("\x00")
        return cls(
            version=version,
            flags=flags,
            l0_index=l0,
            l1_index=l1,
            l2_index=l2,
            root_key_id=root_key_id,
            additional_info=additional_info,
            domain_name=domain_name,
            forest_name=forest_name,
            raw=blob,
        )

@dataclass
class GmsaAccount:
    name: str
    dn: str
    sid: str
    managed_password_id: Optional[ManagedPasswordId]

    def password_materials(self) -> dict:
        mp = self.managed_password_id
        out = {
            "name": self.name,
            "dn": self.dn,
            "sid": self.sid,
        }
        if mp is not None:
            out.update(
                {
                    "root_key_id": str(mp.root_key_id),
                    "l0_index": mp.l0_index,
                    "l1_index": mp.l1_index,
                    "l2_index": mp.l2_index,
                    "domain_name": mp.domain_name,
                    "forest_name": mp.forest_name,
                    "managed_password_id_b64": __import__("base64").b64encode(mp.raw).decode(),
                }
            )
        return out

def derive_password_for_account(
    account: GmsaAccount, root_key_data: bytes, hash_name: str
) -> bytes:
    mp = account.managed_password_id
    if mp is None:
        raise ManagedPasswordIdError(
            f"account {account.name} has no readable msDS-ManagedPasswordID"
        )
    return gkdi.derive_gmsa_password(
        root_key_data,
        mp.root_key_id,
        mp.gkid,
        account.sid,
        hash_name,
    )
