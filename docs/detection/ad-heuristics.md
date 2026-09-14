# Active Directory Heuristics (`detectors/directory.rs`)

Active Directory is the primary identity store in enterprise environments and the central target for advanced threat actors. The `directory.rs` module contains specialized detection logic tuned specifically for Active Directory attack mechanics.

---

## Targeted AD Attack Scenarios

### 1. AS-REP Roasting (`T1558.004`)
- **Mechanism:** Accounts with `"Do not require Kerberos preauthentication"` (`DONT_REQ_PREAUTH`) configured allow anyone to request an AS-REP ticket without knowing the password. The encrypted ticket can then be cracked offline.
- **Log Signature:**
  - Event ID: `4768` (Kerberos Authentication Ticket / AS-REQ).
  - Pre-Authentication Type: `0` (None).
  - Ticket Encryption Type: `0x17` (RC4-HMAC-MD5) or `0x12` (AES256).
- **Detector Rule:**
  ```rust
  if event.activity == "kerberos_as_req" 
     && event.preauth_type == Some(0) 
     && event.ticket_encryption.is_some() {
      // Emit ad_asreproast signal
  }
  ```

---

### 2. Kerberoasting (`T1558.003`)
- **Mechanism:** Any authenticated domain user can request Kerberos Service Tickets (TGS-REQ) for service accounts registered with a Service Principal Name (SPN). The ticket is encrypted with the service account's NTLM password hash and cracked offline.
- **Log Signature:**
  - Event ID: `4769` (Kerberos Service Ticket Request / TGS-REQ).
  - Target SPN: Not `krbtgt`, not a machine account (`*$` format).
  - Ticket Encryption: Requested as `0x17` (RC4-HMAC) even when domain supports AES.
  - Multi-Target Burst: Single user requesting multiple high-privilege SPNs (e.g. `MSSQLSvc/`, `HTTP/`) in short succession.
- **Detector Rule:**
  Tracks distinct service ticket requests per user in a 120-second sliding window. When count $> 3$, emits `ad_kerberoasting`.

---

### 3. DCSync Directory Secret Replication (`T1003.006`)
- **Mechanism:** The Directory Replication Service Remote Protocol (MS-DRSR / DRSUAPI) allows domain controllers to synchronize user credentials and Kerberos keys via `DsGetNCChanges`. Attackers using tools like Impacket's `secretsdump.py` or Mimikatz simulate a DC to pull all domain password hashes.
- **Log Signature:**
  - Protocol: DRSUAPI RPC binding.
  - API Invocation: `DsGetNCChanges` / `IDL_DRSGetNCChanges`.
  - Source Verification: The requesting IP or host is **not** in the domain controller asset registry (`!is_domain_controller(src_ip)`).
- **Detector Rule:**
  ```rust
  if event.activity == "drsuapi_replication" && !is_dc_asset(event.src_ip) {
      // Critical severity signal: Immediate Domain Compromise Attempt
      emit_signal("ad_dcsync", Severity::Critical);
  }
  ```

---

### 4. SMB Lateral Movement & Admin Shares (`T1021.002`)
- **Mechanism:** Adversaries with compromised administrator credentials connect to remote administrative shares (`ADMIN$`, `C$`, `IPC$`) to stage binaries or execute commands via Service Control Manager (`svcctl`) or Scheduled Tasks (`atsvc`).
- **Log Signature:**
  - Event ID: `5140` / `5145` (Network share object access) or Samba `full_audit` connect.
  - Share Name: `\\*\ADMIN$` or `\\*\C$`.
  - Access Mask: Write/Modify permissions granted over network socket.
- **Detector Rule:**
  Emits `ad_lateral_movement_smb` linking source client host and target destination server.
