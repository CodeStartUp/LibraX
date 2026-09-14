# Adversary Campaign & Log Shipper (`lab/attacker/` & `lab/shipper/`)

The adversary container (`attacker`) executes real-world offensive techniques against the lab Domain Controller using standard offensive tooling. The shipper container (`shipper`) captures the generated audit stream in real time and pipes it into the LibraX ingest API.

---

## Adversary Campaign Phases (`lab/attacker/attack.sh`)

The attack runner executes a 5-stage staged attack campaign with realistic inter-phase delays:

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as attacker (172.30.0.66)
    participant DC as Samba AD DC (172.30.0.10)
    participant Shipper as ship.py
    participant LibraX as LibraX Engine (:8080)

    Note over Attacker,DC: Phase 1: Password Spraying
    Attacker->>DC: smbclient NTLM spray across users.txt
    DC-->>Shipper: auth_json_audit (NTLM 0xC000006A)
    Shipper->>LibraX: POST /api/v1/events (ad_password_spray signal)

    Note over Attacker,DC: Phase 2: AS-REP Roasting
    Attacker->>DC: Impacket GetNPUsers.py (AS-REQ no pre-auth)
    DC-->>Shipper: auth_json_audit (AS-REQ type 0)
    Shipper->>LibraX: POST /api/v1/events (ad_asreproast signal)

    Note over Attacker,DC: Phase 3: Kerberoasting
    Attacker->>DC: Impacket GetUserSPNs.py (TGS-REQ for MSSQLSvc)
    DC-->>Shipper: authz_json_audit (TGS-REQ RC4 ticket)
    Shipper->>LibraX: POST /api/v1/events (ad_kerberoasting signal)

    Note over Attacker,DC: Phase 4: DCSync Directory Secret Extraction
    Attacker->>DC: Impacket secretsdump.py (DRSUAPI DsGetNCChanges)
    DC-->>Shipper: Samba debug replication log
    Shipper->>LibraX: POST /api/v1/events (ad_dcsync Critical signal)

    Note over Attacker,DC: Phase 5: SMB Lateral Movement
    Attacker->>DC: smbclient connect to ADMIN$ & C$
    DC-->>Shipper: full_audit tree connect
    Shipper->>LibraX: POST /api/v1/events (ad_lateral_movement_smb signal)

    Note over LibraX: Correlation Engine merges signals into Incident #1
```

---

## Log Shipper Mechanics (`lab/shipper/ship.py`)

The Python log shipper runs as a continuous daemon tailing `/var/log/samba`:

```python
# Regex parser for Samba full_audit VFS connects
FULL_AUDIT = re.compile(
    r"([^|\s][^|]*)\|([0-9a-fA-F:.]+)\|connect\|(ok|fail)\|([^|]+?)\s*$"
)

# Detects DRSUAPI replication from non-DC hosts
GETNCCHANGES = re.compile(r"getncchanges|DsGetNCChanges", re.IGNORECASE)
```

1. **Stateful Tailing:** Tracks file byte offsets across `/var/log/samba/log.samba` and per-client log files.
2. **Schema Mapping:** Converts JSON authentication payloads and VFS connect strings into `RawEvent` JSON payloads.
3. **HTTP Batching:** Emits micro-batches to `http://api:8080/api/v1/events` every 1.0 second.
