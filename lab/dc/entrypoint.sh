#!/bin/bash
# Provision the domain once, then run Samba in the foreground.
#
# Everything here is a real directory operation: samba-tool provisions an actual
# AD domain and creates real accounts. The only thing that makes this a lab is
# that the passwords are weak on purpose, so the attacker container has something
# to find.
set -euo pipefail

REALM="${REALM:-LIBRAX.LOCAL}"
DOMAIN="${DOMAIN:-LIBRAX}"
ADMIN_PASS="${ADMIN_PASS:-LibraX-Admin-2026!}"
VICTIM_PASS="${VICTIM_PASS:-Winter2026!}"
# The password shared by the ordinary accounts (a realistic weak-password reuse the
# attacker leverages for Kerberos ticket requests) and the service account's, kept
# in sync with the attacker container via the same environment variables.
SHARED_PASS="${SHARED_PASS:-Autumn-2025-Placeholder!}"
SVC_PASS="${SVC_PASS:-Sup3rSecret-Svc-2025!}"
LOGDIR=/var/log/samba

mkdir -p "$LOGDIR"

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "[dc] provisioning $REALM ..."
    # Clear any partial state left by an earlier failed provision so samba-tool
    # starts from a clean directory (the volume itself is kept).
    rm -rf /var/lib/samba/* /etc/samba/smb.conf 2>/dev/null || true

    samba-tool domain provision \
        --use-rfc2307 \
        --realm="$REALM" \
        --domain="$DOMAIN" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="$ADMIN_PASS"

    cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf

    echo "[dc] creating accounts ..."
    # A population to enumerate. Ordinary users first, all sharing one weak password.
    for u in alice bob carol dave erin frank grace heidi ivan judy; do
        samba-tool user create "$u" "$SHARED_PASS" \
            --given-name="$u" --surname="User" >/dev/null
    done

    # The one account whose password the attacker will actually guess.
    samba-tool user create victim "$VICTIM_PASS" \
        --given-name="Vic" --surname="Timms" >/dev/null

    # A service account with an SPN: a Kerberoasting target.
    samba-tool user create svc_sql "$SVC_PASS" \
        --given-name="SQL" --surname="Service" >/dev/null
    samba-tool spn add "MSSQLSvc/dc01.${REALM,,}:1433" svc_sql >/dev/null || true

    echo "[dc] provisioning complete"
fi

# Turn on JSON authentication + authorization auditing, in the [global] section
# where global directives actually take effect. auth_json_audit covers every logon
# attempt (NTLM and Kerberos); authz_json_audit covers service access (SMB, LDAP).
#
# Applied on EVERY boot (not just first provision) so it self-corrects a smb.conf
# left misconfigured by an earlier build, without deleting the volume. The block is
# delimited by markers: any prior copy is stripped, then a fresh one is inserted
# immediately after the [global] header.
ensure_audit_config() {
    local conf=/etc/samba/smb.conf
    [ -f "$conf" ] || return 0

    # 1. Drop any previously-inserted LibraX audit block, wherever it landed, plus
    #    any stray audit directive an earlier build appended into a share section
    #    (which Samba ignores with a noisy "Global parameter found in service
    #    section" warning). Section-aware so the real [global] copy is untouched.
    awk '
        /^\[global\]/ { inglobal = 1; print; next }
        /^\[/         { inglobal = 0; print; next }
        /# >>> librax audit >>>/ { skip = 1; next }
        /# <<< librax audit <<</ { skip = 0; next }
        skip { next }
        !inglobal && /^[[:space:]]*(logging|log level|log file|max log size)[[:space:]]*=/ { next }
        { print }
    ' "$conf" > "$conf.tmp"

    # 2. Insert a fresh block right after the [global] header.
    #    auth_json_audit  -> every logon (NTLM + Kerberos KDC ticket issuance).
    #    full_audit       -> SMB tree connects. The file server (smbd) does NOT know
    #                        the authz_json_audit class, so SMB access must be audited
    #                        with the full_audit VFS module instead. syslog=no routes
    #                        its records to the Samba log file the shipper tails, as
    #                        lines of the form "<user>|<ip>|connect|ok|<share>".
    awk '
        /^\[global\]/ && !done {
            print
            print "\t# >>> librax audit >>>"
            print "\tlogging = file"
            print "\tlog file = /var/log/samba/log.%m"
            print "\tlog level = 1 auth_json_audit:3 full_audit:1 drs_repl:5"
            print "\tmax log size = 50000"
            print "\tvfs objects = dfs_samba4 acl_xattr full_audit"
            print "\tfull_audit:success = connect"
            print "\tfull_audit:failure = connect"
            print "\tfull_audit:prefix = %u|%I"
            print "\tfull_audit:syslog = no"
            # Run the DC itself at functional level 2016 so the KDC emits JSON audit
            # records for issued Kerberos tickets (the 2012+ Auth-Policies feature).
            print "\tad dc functional level = 2016"
            print "\t# <<< librax audit <<<"
            done = 1
            next
        }
        { print }
    ' "$conf.tmp" > "$conf"
    rm -f "$conf.tmp"
    echo "[dc] JSON audit logging ensured in [global]"
}

ensure_audit_config

# With the DC now advertising functional level 2016 (via smb.conf above), raise the
# domain and forest to match. Done offline against the local database before samba
# starts; idempotent, so it is a no-op once already at 2016.
ensure_functional_level() {
    local sam=/var/lib/samba/private/sam.ldb
    [ -f "$sam" ] || return 0
    if samba-tool domain level show -H "$sam" 2>/dev/null | grep -q "Domain function level: (Windows) 2016"; then
        return 0
    fi
    echo "[dc] raising domain/forest functional level to 2016 ..."
    samba-tool domain level raise -H "$sam" \
        --domain-level=2016 --forest-level=2016 2>&1 | tail -2 || true
}

ensure_functional_level

# Point the DC's own resolver at itself so internal DNS resolves.
echo "nameserver 127.0.0.1" > /etc/resolv.conf || true

echo "[dc] starting samba (logs -> /var/log/samba)"
# The main samba process (which hosts the KDC) writes its Kerberos audit records to
# stdout, while the smbd children write NTLM/SMB and full_audit records to the
# log.%m files. So tee stdout to a file on the shared volume too, giving the shipper
# the Kerberos telemetry while keeping it visible in `docker logs`. Full path: the
# AD DC daemon lives in /usr/sbin, which is not always on the exec PATH.
exec /usr/sbin/samba --interactive 2>&1 | tee -a /var/log/samba/log.kdc-stdout
