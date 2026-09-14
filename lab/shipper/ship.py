#!/usr/bin/env python3
"""Ship Samba JSON audit records into LibraX.

Samba, with ``auth_json_audit`` and ``authz_json_audit`` enabled, writes one JSON
record per authentication attempt and per service authorization. This tails those
log files and forwards each record to the LibraX ingest endpoint as a raw event,
shaped exactly the way the ``directory_live`` parser and the live-directory
detectors expect.

It invents nothing: one Samba record becomes one raw event. Whether a flood of
them is an attack is decided by LibraX, not here.
"""
import glob
import json
import os
import re
import time
from datetime import datetime, timezone

import requests

API_URL = os.environ.get("LIBRAX_API_URL", "http://api:8080").rstrip("/")
INGEST = f"{API_URL}/api/v1/events"
LOG_DIR = os.environ.get("SAMBA_LOG_DIR", "/var/log/samba")
SOURCE_ID = os.environ.get("SOURCE_ID", "dc-samba-01")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "1.0"))

# "ipv4:172.30.0.66:41022" / "ipv6:::1:445" -> the address only.
ADDR = re.compile(r"(?:ipv4|ipv6):\[?([0-9a-fA-F:.]+?)\]?(?::\d+)?$")

# Samba's full_audit VFS module logs SMB tree connects as one line per connect,
# shaped by our "full_audit:prefix = %u|%I":  "<user>|<ip>|connect|ok|<share>".
# This is how SMB access is audited: the file server does not emit JSON authz.
FULL_AUDIT = re.compile(
    r"([^|\s][^|]*)\|([0-9a-fA-F:.]+)\|connect\|(ok|fail)\|([^|]+?)\s*$"
)

# The DRSUAPI replication handler firing server-side is the DCSync signature: a host
# that is not a domain controller pulling directory secrets via DsGetNCChanges. Samba
# emits no JSON audit for serving it, but does log the handler in its debug stream.
GETNCCHANGES = re.compile(r"getncchanges|DsGetNCChanges", re.IGNORECASE)

# The IP/account of the most recent DRSUAPI (DCE/RPC) bind, used to attribute a
# replication pull to the host that requested it.
last_dcerpc = {}

start_tag = int(time.time())
seq = 0


def now_rfc3339():
    return datetime.now(timezone.utc).isoformat()


def parse_addr(value):
    if not value:
        return None
    m = ADDR.match(value)
    return m.group(1) if m else value


def next_id():
    global seq
    seq += 1
    return f"AD-{start_tag}-{seq:07d}"


def to_event(obj):
    """Map one Samba audit record to a LibraX raw event, or None to skip."""
    kind = obj.get("type")

    if kind == "Authentication":
        a = obj.get("Authentication", {})
        status = a.get("status") or ""
        # Kerberos KDC records carry the account as "user@REALM"; NTLM/SMB records
        # carry the bare "user". Strip the realm so the same principal reads the same
        # across detectors and correlates into one entity.
        account = a.get("clientAccount") or a.get("mappedAccount") or ""
        if "@" in account:
            account = account.split("@", 1)[0]
        payload = {
            "event_kind": "auth",
            "success": status == "NT_STATUS_OK",
            "status": status,
            "protocol": a.get("serviceDescription") or "",
            "auth_description": a.get("authDescription") or "",
            "password_type": a.get("passwordType") or "",
            "TargetUserName": account,
            "client_domain": a.get("clientDomain") or "",
            "WorkstationName": a.get("workstation") or "",
            "IpAddress": parse_addr(a.get("remoteAddress")),
        }
        return payload

    if kind == "Authorization":
        z = obj.get("Authorization", {})
        service = (z.get("serviceDescription") or "").lower()
        # Replication (DRSUAPI) is the DCSync signature; SMB/LDAP authorizations
        # are ordinary service access we still want visible in the telemetry.
        if "drs" in service or "replicat" in service:
            operation = "drsuapi"
        elif "smb" in service:
            operation = "connect"
        else:
            operation = service or "authorize"
        return {
            "event_kind": "smb",
            "operation": operation,
            "success": True,
            "status": "NT_STATUS_OK",
            "protocol": z.get("serviceDescription") or "",
            "TargetUserName": z.get("account") or "",
            "client_domain": z.get("domain") or "",
            "IpAddress": parse_addr(z.get("remoteAddress")),
        }

    return None


def extract_records(line):
    """Pull JSON audit objects out of a Samba log line."""
    idx = line.find("{")
    if idx < 0:
        return
    chunk = line[idx:]
    try:
        obj = json.loads(chunk)
    except json.JSONDecodeError:
        return
    if isinstance(obj, dict) and obj.get("type") in ("Authentication", "Authorization"):
        yield obj


def replication_event():
    """A directory_replication event attributed to the last DRSUAPI bind, or None."""
    ip = last_dcerpc.get("ip")
    if not ip:
        return None
    return {
        "event_kind": "smb",
        "operation": "drsuapi",
        "success": True,
        "status": "NT_STATUS_OK",
        "protocol": "DRSUAPI",
        "TargetUserName": last_dcerpc.get("user") or "",
        "IpAddress": ip,
    }


def parse_full_audit(line):
    """Map a Samba full_audit SMB connect line to a LibraX raw event, or None."""
    m = FULL_AUDIT.search(line)
    if not m:
        return None
    user, ip, result, share = m.groups()
    user = user.strip()
    share = share.strip()
    if not ip or user in ("", "-"):
        return None
    return {
        "event_kind": "smb",
        "operation": "connect",
        "success": result == "ok",
        "status": "NT_STATUS_OK" if result == "ok" else "NT_STATUS_ACCESS_DENIED",
        "protocol": "SMB",
        "TargetUserName": user,
        "IpAddress": ip.strip(),
        "share": share,
    }


def post(events):
    if not events:
        return
    for i in range(0, len(events), 200):
        batch = events[i : i + 200]
        try:
            r = requests.post(INGEST, json={"events": batch}, timeout=10)
            if r.status_code >= 300:
                print(f"[shipper] ingest {r.status_code}: {r.text[:200]}", flush=True)
            else:
                print(f"[shipper] shipped {len(batch)} events", flush=True)
        except requests.RequestException as exc:
            print(f"[shipper] ingest error: {exc}", flush=True)


def wait_for_api():
    health = f"{API_URL}/api/v1/health"
    for _ in range(60):
        try:
            if requests.get(health, timeout=3).status_code < 300:
                print("[shipper] API is up", flush=True)
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    print("[shipper] giving up waiting for API; shipping anyway", flush=True)


def main():
    print(f"[shipper] watching {LOG_DIR}, shipping to {INGEST}", flush=True)
    wait_for_api()

    offsets = {}
    while True:
        events = []
        for path in sorted(glob.glob(os.path.join(LOG_DIR, "*"))):
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                start = offsets.get(path, 0)
                if size < start:  # rotated/truncated
                    start = 0
                if size == start:
                    continue
                with open(path, "r", errors="replace") as fh:
                    fh.seek(start)
                    data = fh.read()
                    offsets[path] = fh.tell()
            except OSError:
                continue

            def emit(payload):
                if payload is None or not payload.get("IpAddress"):
                    return
                events.append(
                    {
                        "raw_id": next_id(),
                        "source_type": "active_directory",
                        "source_id": SOURCE_ID,
                        "received_at": now_rfc3339(),
                        "payload": payload,
                    }
                )

            seen_replication = set()
            for line in data.splitlines():
                matched = False
                for obj in extract_records(line):
                    payload = to_event(obj)
                    emit(payload)
                    matched = True
                    # Remember the DRSUAPI bind so a following replication pull can be
                    # attributed to the host and account that made it.
                    if payload and payload.get("protocol") == "DCE/RPC":
                        last_dcerpc["ip"] = payload.get("IpAddress")
                        last_dcerpc["user"] = payload.get("TargetUserName")
                if matched:
                    continue
                # Non-JSON lines may be full_audit SMB connects or DRSUAPI handler logs.
                fa = parse_full_audit(line)
                if fa:
                    emit(fa)
                elif GETNCCHANGES.search(line):
                    rep = replication_event()
                    # One replication event per source per read; the detector
                    # aggregates, and a pull logs the handler many times.
                    if rep and rep["IpAddress"] not in seen_replication:
                        seen_replication.add(rep["IpAddress"])
                        emit(rep)

        post(events)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
