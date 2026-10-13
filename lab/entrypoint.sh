#!/bin/bash
set -euo pipefail

SAMBA_CONF=/usr/local/samba/etc/smb.conf
REALM="${REALM:-lab.local}"
DOMAIN="${DOMAIN:-LAB}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin123!}"
GMSA_NAME="${GMSA_NAME:-svcgmsa}"
LOWPRIV_USER="${LOWPRIV_USER:-lowpriv}"
LOWPRIV_PASSWORD="${LOWPRIV_PASSWORD:-Lowpriv123!}"

if [ ! -f "$SAMBA_CONF" ]; then
    echo "[entrypoint] no smb.conf: provisioning AD DC for realm ${REALM}..."

    samba-tool domain provision \
        --realm="$REALM" \
        --domain="$DOMAIN" \
        --server-role="domain controller" \
        --dns-backend=NONE \
        --adminpass="$ADMIN_PASSWORD" \
        --use-rfc2307

    SAM_LDB=/usr/local/samba/private/sam.ldb

    echo "[entrypoint] creating KDS root key (backdated 11h)..."
    samba-tool domain kds root-key create \
        -H "$SAM_LDB" \
        --use-start-time="$(date -u -d '11 hours ago' +'%Y-%m-%dT%H:%M:%S')"

    echo "[entrypoint] creating gMSA ${GMSA_NAME}$..."
    samba-tool service-account create \
        -H "$SAM_LDB" \
        --name="$GMSA_NAME" \
        --dns-host-name="${GMSA_NAME}.${REALM}"

    echo "[entrypoint] creating user ${LOWPRIV_USER}..."
    samba-tool user create "$LOWPRIV_USER" "$LOWPRIV_PASSWORD" -H "$SAM_LDB"

    echo "[entrypoint] provision complete."
fi

echo "[entrypoint] starting samba AD DC (Samba $(samba --version))..."
exec samba -i --no-process-group
