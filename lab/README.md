# LibraX live Active Directory attack lab

This is the "real, not demo" path for LibraX. Instead of the simulator, it stands
up a **real Active Directory domain controller**, runs **real attacks** against it
with **real offensive tools**, and streams the DC's **real audit logs** into
LibraX, where a genuine incident assembles in the dashboard.

```
attacker (Impacket, smbclient)  ─attacks→  dc (Samba AD: Kerberos, LDAP, SMB)
                                                    │ JSON audit logs
                                                    ▼
                                              shipper (tails logs)
                                                    │ POST /api/v1/events
                                                    ▼
                                              LibraX api  ──►  dashboard :3000
```

Nothing here touches a system you do not own: it is one private Docker network
(`172.30.0.0/24`), and no destructive action is taken against any real host.

## Run it

```bash
docker compose -f lab/docker-compose.yml up --build
```

Then open **http://localhost:3000**. The console starts **empty** (real mode, no
simulated data). Within a couple of minutes the attacker finishes its first
campaign and an incident appears in the queue.

First build is slow — the API image compiles the Rust workspace, and the DC image
installs and provisions Samba. Subsequent runs are fast.

## What actually happens

The attacker container (`lab/attacker/attack.sh`) runs a staged campaign, each
phase a real tool over a real protocol:

| Phase | Tool | Protocol | LibraX detection | ATT&CK |
|------|------|----------|------------------|--------|
| 1. Password spray | `smbclient` loop | NTLM/SMB | `ad_password_spray` | T1110.003 / T1110.001 |
| 2. Account enumeration (TGT sweep) | `GetNPUsers.py` + `getTGT.py` | Kerberos | `ad_kerberos_abuse` | T1087.002 / T1558.003 |
| 3. Valid logon + share sweep | `smbclient` | NTLM/SMB | raises spray to **High**, `ad_smb_enum` | T1078 / T1135 |
| 4. Kerberoast | `GetUserSPNs.py` | Kerberos | `ad_kerberos_abuse` (roasting) | T1558.003 |
| 5. DCSync | `secretsdump.py -just-dc` | DRSUAPI | `ad_dcsync` | T1003.006 |

All four directory detectors fire on genuinely audited DC telemetry, and correlate
into a single incident whose MITRE map spans the whole chain (spraying → account
discovery → kerberoasting → share discovery → DCSync). The console shows **only**
these real events — the simulator's synthetic noise is off in real mode.

The domain controller has weak passwords on purpose and a Kerberoastable service
account (`svc_sql` with an SPN). The account whose password the spray "guesses"
is `victim` / `Winter2026!`; the ordinary accounts share one reused password the
attacker leverages for the Kerberos TGT sweep.

LibraX does the detection, not the shipper: the shipper forwards one raw event per
Samba audit record, and the aggregating detectors in `librax-detection`
(`detectors/directory.rs`) turn the flood into one explained finding.

## How the DC is configured for real audit telemetry

Getting a Samba AD DC to emit all of this to disk took specific configuration
(`lab/dc/entrypoint.sh`), worth recording because it is not obvious:

- **Kerberos** — the KDC only writes JSON audit for issued tickets at **functional
  level 2012+** (Authentication-Policies feature). The DC provisions, then sets
  `ad dc functional level = 2016` and raises the domain/forest to 2016. The KDC
  also writes those records to **stdout**, not the `log.%m` files, so the entrypoint
  tees stdout to `log.kdc-stdout` for the shipper.
- **SMB tree connects** — the file server (`smbd`) does **not** know the
  `authz_json_audit` class, so SMB access is captured with the **`full_audit` VFS
  module** (`full_audit:syslog = no` routes it to the log file); the shipper parses
  those `user|ip|connect|ok|share` lines.
- **DCSync** — Samba emits no JSON audit for serving a replication pull, but logs
  the `DsGetNCChanges` handler under `drs_repl`; the shipper turns that (attributed
  to the preceding DRSUAPI bind) into a `directory_replication` event.
- **NTLM auth** — `auth_json_audit` to the per-machine `log.%m` files, out of the box.

The DC image is Debian 13 (Samba 4.22 — 4.17 has no KDC audit at all) and needs
the `samba-ad-dc` package for the `/usr/sbin/samba` daemon. The attacker uses
Impacket 0.13.1 with `setuptools<81` (for `pkg_resources`).

## Re-running the attack

By default the campaign runs once. To watch a fresh incident build, re-run it:

```bash
docker compose -f lab/docker-compose.yml exec attacker /usr/local/bin/attack.sh
```

Or loop it automatically:

```bash
ATTACK_REPEAT=true docker compose -f lab/docker-compose.yml up -d attacker
```

Clear the console between runs from the dashboard's **Attack range → reset**, or:

```bash
curl -X POST http://localhost:8080/api/v1/reset
```

## Watching the pieces

```bash
docker compose -f lab/docker-compose.yml logs -f attacker   # the attack itself
docker compose -f lab/docker-compose.yml logs -f shipper    # events being shipped
docker compose -f lab/docker-compose.yml logs -f dc         # samba
```

Confirm real events arrived:

```bash
curl "http://localhost:8080/api/v1/events/search?source_type=active_directory&limit=5"
curl "http://localhost:8080/api/v1/incidents"
```

## Upgrading to a real Windows Server AD

Samba is a real directory service, but it is not Windows. To use genuine Windows
AD instead of the Samba DC, without changing LibraX:

1. Stand up a Windows Server VM (Hyper-V, VMware, or VirtualBox), promote it to a
   domain controller (`Install-ADDSForest`), and install **Sysmon**.
2. Ship its logs to LibraX. Any forwarder works (Winlogbeat, NXLog, a scheduled
   PowerShell task) as long as each record is POSTed to
   `POST /api/v1/events` with `source_type: "active_directory"` and a payload
   carrying `TargetUserName`, `IpAddress`, `success`/`status`, and `protocol`
   — the same fields the shipper sends here (see `directory_live` in
   `crates/librax-normalizer/src/parsers.rs`).
3. Point the VM at the same network as the lab (or run LibraX on the host) and
   run the attacks from a second VM or the attacker container.

The ingestion path, parsers, and detectors are identical; only the source of the
logs changes.
