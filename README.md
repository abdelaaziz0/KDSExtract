# KDSExtract

Full-chain exploit for **CVE-2026-58222** (Samba AD DC LDAP `Compare`
filter injection + trusted-request confusion): an ordinary domain user
recovers confidential attributes — notably the KDS root key — and
derives gMSA passwords offline.

```
low-priv user ──LDAP Compare "attr>="──> ordered oracle ──> msKds-RootKeyData
                                                                      │
             MS-GKDI (SP 800-108, ported from Samba)                  ▼
low-priv user <──────────── gMSA password + NT hash ─────── Golden gMSA chain
```

Authorized-lab use only. The vulnerability is publicly documented
(Samba advisory, patch, MS-GKDI spec); this project packages it.

## Install

```
pip install .        # Python >= 3.9, no runtime dependencies
pytest               # 45 tests, incl. Samba's own GKDI vectors
```

## Usage

```
kdsextract check      --host dc --user lowpriv@lab.local
kdsextract list-keys  --host dc --user lowpriv@lab.local
kdsextract recover    --host dc --user lowpriv@lab.local --key <guid>
kdsextract list-gmsa  --host dc --user lowpriv@lab.local
kdsextract dump-gmsa --host dc --user lowpriv@lab.local --name 'svcgmsa$' --verify-bind
kdsextract pwn       --host dc --user lowpriv@lab.local --verify-bind
```

Password via `--password`, `KDSEXTRACT_PASSWORD`, or prompt. `--json`
for machine-readable output. Plain LDAP first, auto-fallback to LDAPS
(636) — Samba rejects plaintext simple binds and has no StartTLS.

`check`:

```
VULNERABLE (CVE-2026-58222): injected compare evaluates and confidential attributes participate
NOT VULNERABLE: attribute operator injection rejected (invalidAttributeSyntax 21) -- fixed Samba
```

`pwn` (from the lab, trimmed):

```
verdict: VULNERABLE

root keys:
  effd1d54-... (gmsa-reference): 802da1146c207a75...  (576 queries)

gMSA svcgmsa$  (sid S-1-5-21-...)
  root key effd1d54-... hash=SHA512 gkid=364,15,14
  password (utf-16 hex): 73764bf424123f6b...
  NT hash: cf30eb5212fe22e696bea95f02010e05
```

## How it works

Samba's vulnerable `Compare` path built its internal filter with
`talloc_asprintf("(%s=%*s)", attribute, len, data)`: no attribute-name
validation, no value escaping. A trailing `>` turns the comparison into
`>=`, and the internal search ran without `DSDB_MARK_REQ_UNTRUSTED`, so
confidential attributes participate despite being redacted from Search.

Each `Compare` answers "stored >= candidate?" (`ldb_comparison_binary`
order: memcmp, shorter-is-less), so a per-byte binary search recovers
the whole value. Every candidate byte is sent `\XX`-escaped — the
embedded string stays printable, so `printf("%*s")` cannot truncate at
NUL — and `ldb_parse_tree` unescapes it server-side. Cost: 8-9
compares per byte, ~576 for the 64-byte root key.

With the root key, the gMSA password falls offline: SP 800-108
counter-mode HMAC (hash from `msKds-KDFParam`), the
`GkdiDerivationCtx` serialization, the L0 → L1 → L2 seed-key walk
(labels `"KDS service"` / `"GMSA PASSWORD"` in UTF-16LE), and the
256-byte password with NUL post-processing. The port is byte-exact
with Samba — its 12 test vectors are in the test suite. When
`msKds-KDFParam` is hidden (Samba hides root key attributes from
ordinary users), both platform defaults are derived: SHA512
(Samba-created keys, confirmed correct live) then SHA256 (Windows).

## The lab

```
cd lab
./run-demo.sh
```

Builds Samba **4.24.4** (vulnerable) and **4.24.5** (fixed) from
upstream git tags, provisions identical domains (`lab.local`, KDS root
key backdated one 10h key cycle, gMSA `svcgmsa$`, user `lowpriv`), then
asserts end to end:

| check | dc-vuln (4.24.4) | dc-fixed (4.24.5) |
|---|---|---|
| injected `>=` compare | evaluates (oracle live) | rejected, code 21 |
| `msKds-RootKeyData` | recovered, byte-exact vs DC ground truth | n/a |
| derived gMSA password | NT hash == DC's stored `unicodePwd` | n/a |

Root-key ground truth comes from `samba-tool domain kds root-key list
--show-secrets`, password ground truth from `samba-tool user getpassword`
(Samba computes the managed password on the fly). The demo exits 0
only if every assertion holds. `docker compose down -v` for a fresh
provision.

Note: Samba search-hides `msKds-ProvRootKey` objects from ordinary
users, so discovery flows gMSA → `msDS-ManagedPasswordID` → root key
DN (GoldenGMSA's flow) — the Compare oracle needs no search rights.

## Limitations

* TLS peer verification skipped (lab DC certs are self-signed).
* gMSA passwords are 128 UTF-16 chars; a small fraction contain unpaired
  surrogates that can't round-trip a simple-bind *string* — the tool
  reports this; the bytes and NT hash are still exact (the lab proves
  it against the DC).
* Kerberos AS-REQ (NT-hash-keyed RC4) verification would avoid the
  string issue entirely — future work.

## Fix / detection

Fixed in Samba **4.24.5 / 4.23.10 / 4.22.11** (2026-07-28). The patch
validates the attribute name (`ldb_valid_attr_name`), binary-encodes
the value (`ldb_binary_encode`), and marks the internal search
untrusted. Detection: bursts of Compares from one connection, attribute
descriptions ending in `>`, targeting `CN=Master Root Keys` objects;
code-21 responses identify patched DCs.

## Credits

CVE-2026-58222 reported by OpenAI Security Research (Samba bug 16148);
patches by Stefan Metzmacher / SerNet. GKDI derivation ported from
Samba (GPL-3.0) and cross-checked against
[GoldenGMSA](https://github.com/Semperis/GoldenGMSA) (MIT). Advisory:
<https://www.samba.org/samba/security/CVE-2026-58222.html>. This
project's code: MIT.
