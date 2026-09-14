# Attacker workstation.
#
# Real, well-known offensive tools (Impacket, smbclient, kinit) pointed at the
# lab domain controller. Nothing here is malware: these are the same utilities a
# red team uses, and they run only against the DC on this private network.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        smbclient krb5-user ldap-utils dnsutils iputils-ping netcat-openbsd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# impacket 0.12 imports pkg_resources at startup. python:3.12-slim no longer ships
# setuptools, and setuptools >= 81 has removed pkg_resources entirely, so pin an
# older setuptools that still provides it.
RUN pip install --no-cache-dir "setuptools<81" impacket==0.13.1

COPY attack.sh /usr/local/bin/attack.sh
COPY wordlists /opt/wordlists
RUN chmod +x /usr/local/bin/attack.sh

ENTRYPOINT ["/usr/local/bin/attack.sh"]
