# Samba Active Directory domain controller.
#
# A real DC: real Kerberos KDC, real LDAP, real SMB, real NTLM. It provisions the
# domain on first boot, creates the accounts the attacker will go after, and
# turns on Samba's JSON authentication auditing so every logon attempt is written
# to disk where the shipper can read it.
#
# Debian 13 (trixie) ships Samba 4.22, which -- unlike 4.17 in Debian 12 -- gives
# the KDC JSON audit logging of issued Kerberos tickets (added in 4.19). Without
# it there is no Kerberos telemetry to detect on at all.
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

# Debian 13 split the AD DC daemon (/usr/sbin/samba) out of the `samba` package
# into `samba-ad-dc`; without it only the file server (smbd) is present.
RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-ad-dc samba-ad-provision smbclient samba-dsdb-modules samba-vfs-modules \
        krb5-user winbind ldb-tools python3-samba \
        procps iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# LDAP, SMB, Kerberos, kpasswd, DNS.
EXPOSE 389/tcp 636/tcp 445/tcp 88/tcp 88/udp 464/tcp 53/tcp 53/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
