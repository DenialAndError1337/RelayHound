# RelayHound: Relay Attack Prerequisite Checker

Automated tool to check whether a target Active Directory environment meets the prerequisites for common NTLM and Kerberos relay attacks.

---

## ⚠️ Scope and Intended Use

**RelayHound is a passive reconnaissance tool. It does not perform any exploitation.**

All checks are read-only enumeration queries. No authentication is coerced, no tickets are relayed, no objects are modified, and no payloads are executed. Command suggestions shown in the output (e.g. `printerbug.py`, `ntlmrelayx.py`) are informational text only and are never run by the tool.

This distinction matters in professional engagements where recon and exploitation require separate authorisation. RelayHound falls entirely within the recon phase.

**What RelayHound does:**
- Queries SMB/LDAP/LDAPS/HTTP/MSSQL service state (read-only)
- Checks port reachability
- Reads AD attributes (MachineAccountQuota, DFL, computer objects, ACLs)
- Runs certipy/nxc/bloodyAD in enumeration mode only

**What RelayHound does NOT do:**
- Trigger authentication from any target machine
- Relay any credentials or tickets
- Write to any AD object
- Execute PrinterBug, PetitPotam, or any other coercion tool
- Run ntlmrelayx, krbrelayx, or any relay tool

---

## Installation

**Core dependencies** (installed automatically):

```bash
pip install -r requirements.txt
```

This installs `ldap3`, `rich`, and `impacket`. Enough to run basic checks.

**Optional tools** (recommended for full coverage):

```bash
# netexec — SMB/LDAP/MSSQL checks
apt install netexec

# certipy-ad — ADCS ESC8/ESC11 detection
pip install certipy-ad

# bloodyAD — LDAP ACL and object checks
pip install bloodyad
```

Most checks will fall back gracefully or report SKIP if a tool isn't installed, but coverage will be significantly reduced without them. `nxc` in particular is used across almost every module.

## Quick Start

```bash
# Scan the primary DC only
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 -v

# Include member servers and workstations
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --extra-targets 10.10.10.20 --attacker-ip 10.10.10.99 -v

# Full run with ACL scan to identify coercion targets
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --extra-targets 10.10.10.20 --attacker-ip 10.10.10.99 -v --find-relay-targets
```

#### Specifying Extra Targets

```bash
# Multiple individual IPs
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --extra-targets 10.10.10.20,10.10.10.21,10.10.10.22

# CIDR range
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --extra-targets 10.10.10.0/24

# Dash range
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --extra-targets 10.10.10.20-30

# From a file (one entry per line, # for comments)
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv -p password123 --targets-file targets.txt
```

---

## Usage

```
python relayhound.py [options]

Target:
  -d, --domain              Target domain (e.g. sevenkingdoms.local)    [required]
  --dc-ip                   Primary Domain Controller IP                 [required]
  --extra-targets           Comma-separated IPs, hostnames, CIDR ranges,
                            or dash ranges (e.g. 10.0.0.1,10.0.0.0/24,10.0.0.10-20)
  --attacker-ip             Your Kali/attacker IP (for WebDAV relay check)
  --targets-file            File with target IPs/ranges, one per line (# for                                   comments)

Credentials:
  -u, --username            Domain username (low-privilege account)      [required]
  -p, --password            Plaintext password         [required unless --nt-hash]
  --nt-hash                 NT hash for pass-the-hash

Options:
  -v, --verbose             Show per-check details in terminal
  --parallel                Run attack checks in parallel (faster)
  --timeout N               Network timeout in seconds (default: 10)
  -o, --output FILE         Markdown report path (default:                                                     <domain>_ntlm_relay_report.md)
  --no-report               Skip writing Markdown and HTML reports
  --no-html                 Skip HTML report (keep Markdown only)
  --relay-list FILE         Save SMB unsigned hosts for ntlmrelayx -tf
  --no-relay-list           Skip writing the relay targets file
  --find-relay-targets      Scan nTSecurityDescriptor ACLs to identify which
                            accounts are worth coercing and for which attack
```

---

## Attacks Checked

### 1. NTLM Relay → SMB (secretsdump)

Relay NTLM authentication to SMB on a target where signing is disabled. Allows secretsdump-style extraction of SAM/LSA/NTDS.

| Check                             | Required    | Method                            |
| --------------------------------- | ----------- | --------------------------------- |
| SMB signing disabled on ≥1 target | ✅           | `nxc smb` — parse `signing:False` |
| NTLM authentication enabled       | ✅           | `nxc smb` — check auth success    |
| Non-DC SMB target reachable       | ⚠️ Optional | TCP port 445 check                |
| Null/guest session allowed        | ⚠️ Optional | `nxc smb -u '' -p ''`             |

RelayHound automatically saves a list of SMB unsigned hosts to `<domain>_relay_targets.txt` (or a custom path via `--relay-list`). This file can be passed directly to ntlmrelayx.

**Exploit:** `ntlmrelayx.py -tf relay_targets.txt -smb2support`

---

### 2. NTLM Relay → LDAP (RBCD)

Relay NTLM to LDAP to write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object, enabling Resource-Based Constrained Delegation.

| Check | Required | Method |
|-------|----------|--------|
| LDAP signing not enforced | ✅ | `nxc ldap --module ldap-checker` |
| LDAP channel binding not required | ✅ | `nxc ldap --module ldap-checker` |
| Writable computer object exists | ✅ | `bloodyAD get writable --otype COMPUTER` |
| MachineAccountQuota > 0 | ⚠️ Optional | `nxc ldap --module maq` / ldap3 |
| Domain functional level ≥ 2008 | ⚠️ Optional | ldap3 `msDS-Behavior-Version` |

**Exploit:** `ntlmrelayx.py -t ldaps://<dc> --delegate-access`

---

### 3. NTLM Relay → LDAP (Shadow Credentials)

Relay NTLM to LDAP to write `msDS-KeyCredentialLink` on a target computer object, enabling certificate-based authentication as that account.

| Check | Required | Method |
|-------|----------|--------|
| LDAP signing not enforced | ✅ | `nxc ldap --module ldap-checker` |
| LDAP channel binding not required | ✅ | `nxc ldap --module ldap-checker` |
| Writable computer object exists | ✅ | `bloodyAD get writable --otype COMPUTER` |
| Domain functional level ≥ 2016 | ⚠️ Optional | ldap3 `msDS-Behavior-Version` |
| ADCS or local KDC supports PKINIT | ⚠️ Optional | certipy check |

**Exploit:** `ntlmrelayx.py -t ldaps://<dc> --shadow-credentials --shadow-target <computer>`

---

### 4. NTLM Relay → ADCS (ESC8)

Relay to AD CS web enrollment (certsrv) over HTTP. Allows enrolling a certificate on behalf of the relayed account.

| Check | Required | Method |
|-------|----------|--------|
| AD CS deployed in domain | ✅ | `nxc ldap --module adcs` / certipy / ldap3 |
| Web enrollment HTTP endpoint reachable | ✅ | TCP port 80 + HTTP GET `/certsrv/` |
| certsrv uses NTLM auth | ✅ | `WWW-Authenticate: NTLM` header check |
| certipy confirms ESC8 | ⚠️ Optional | `certipy-ad find -vulnerable` |
| HTTPS certsrv EPA not enforced | ⚠️ Optional | Manual registry check |

**Exploit:** `ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController`

---

### 5. NTLM Relay → ADCS (ESC11 / RPC)

Relay NTLM over RPC to the ICPR interface on the CA server, bypassing the need for HTTP web enrollment.

| Check | Required | Method |
|-------|----------|--------|
| AD CS deployed in domain | ✅ | `nxc ldap --module adcs` / certipy |
| CA RPC port reachable (TCP 135 + dynamic) | ✅ | TCP check |
| `IF_ENFORCES_ENCRYPT_ICPR` flag not set | ✅ | certipy / registry check |
| Enrollable template exists | ⚠️ Optional | certipy |

**Exploit:** `ntlmrelayx.py -t rpc://<ca-host> -rpc-mode ICPR -icpr-ca-name '<ca-name>' --template DomainController`

---

### 6. NTLM Relay → MSSQL

Relay NTLM to SQL Server. Allows `xp_cmdshell` execution depending on privileges of the relayed account.

| Check                                      | Required    | Method                                               |
| ------------------------------------------ | ----------- | ---------------------------------------------------- |
| MSSQL port reachable (TCP 1433)            | ✅           | TCP check + UDP 1434 SQL Browser                     |
| MSSQL accepts Windows/NTLM auth            | ✅           | `nxc mssql`                                          |
| SQL user has direct sysadmin privilege     | ⚠️ Optional | `nxc mssql -q "SELECT IS_SRVROLEMEMBER('sysadmin')"` |
| Impersonation path to sysadmin exists      | ⚠️ Optional | `nxc mssql -q` on `sys.server_permissions`           |
| Linked servers exist                       | ⚠️ Optional | `nxc mssql -q` on `sys.servers`                      |
| WebClient running on target                | ⚠️ Optional | `nxc smb --module webdav`                            |
| xp_dirtree coercion available              | ⚠️ Optional | SQL access confirmed                                 |
| MSSQL service account (SPN enumeration)    | ⚠️ Optional | `impacket-GetUserSPNs` / ldap3                       |
| High-value users logged on to MSSQL server | ⚠️ Optional | `nxc smb --loggedon-users` (requires local admin)    |

**Exploit:** `ntlmrelayx.py -t mssql://<host> -i`

---

### 7. NTLM Relay → HTTP/WebDAV

Coerce a Windows machine to authenticate via WebDAV (HTTP + NTLM), bypassing SMB signing. The WebClient service must be running on the target.

| Check                                  | Required    | Method                     |
| -------------------------------------- | ----------- | -------------------------- |
| WebClient service running on ≥1 target | ✅           | `nxc smb --module webdav`  |
| HTTP relay listener port accessible    | ✅           | TCP port 80 on attacker    |
| SMB signing enforced (bypass needed)   | ⚠️ Optional | `nxc smb` signing check    |
| Coercion method available              | ⚠️ Optional | `nxc smb --module spooler` |

---

### 8. Kerberos Relay → ADCS (krbrelayx + Forshaw DNS)

Relay Kerberos authentication to ADCS using krbrelayx, combined with Forshaw's DNS trick to direct coercion to the attacker.

| Check                                  | Required    | Method             |
| -------------------------------------- | ----------- | ------------------ |
| AD CS deployed with HTTP enrollment    | ✅           | certipy / ldap3    |
| DNS update rights (for Forshaw trick)  | ✅           | `dnstool.py` check |
| Unconstrained delegation target exists | ⚠️ Optional | ldap3              |
| ADCS template allows client auth       | ⚠️ Optional | certipy            |

**Exploit:** `krbrelayx.py --target http://<ca>/certsrv/`

---

### 9. NTLM Relay → LDAP (LAPS Password Dump)

Relay NTLM to LDAP to read `ms-Mcs-AdmPwd` from computer objects where the relayed account has read access.

| Check | Required | Method |
|-------|----------|--------|
| LAPS deployed in domain | ✅ | `nxc ldap --module laps` |
| LDAP signing not enforced | ✅ | `nxc ldap --module ldap-checker` |
| Relayed account can read LAPS passwords | ✅ | `bloodyAD get writable` |

**Exploit:** `ntlmrelayx.py -t ldap://<dc> --dump-laps`

---

### 10. NTLM Relay → LDAPS (Add Computer Account)

Relay NTLM to LDAPS to add a new computer account to the domain (requires MachineAccountQuota > 0).

| Check | Required | Method |
|-------|----------|--------|
| LDAPS reachable (port 636) | ✅ | TCP check |
| LDAPS channel binding not enforced | ✅ | `nxc ldap --module ldap-checker` |
| MachineAccountQuota > 0 | ✅ | `nxc ldap --module maq` / ldap3 |

**Exploit:** `ntlmrelayx.py -t ldaps://<dc> --add-computer`

---

### 11. NTLM Relay → LDAPS (ACL Abuse)

Relay NTLM to LDAPS to modify ACLs on AD objects — granting DCSync rights, adding group members, or writing to computer objects.

| Check | Required | Method |
|-------|----------|--------|
| LDAPS reachable (port 636) | ✅ | TCP check |
| LDAPS channel binding not enforced | ✅ | `nxc ldap --module ldap-checker` |
| Writable high-value AD objects exist | ✅ | `bloodyAD get writable` |
| High-value groups with weak ACLs | ⚠️ Optional | ldap3 |

**Exploit:** `ntlmrelayx.py -t ldaps://<dc> --escalate-user <user>`

---

## Relay Target Finder (`--find-relay-targets`)

When `--find-relay-targets` is passed, RelayHound performs an additional inbound ACL scan using your enumeration credential. Instead of checking what your account can do, it queries `nTSecurityDescriptor` on computer objects, the domain root, and high-value groups to find which principals have write (or read, for LAPS) rights that make them valuable coercion targets.

The output answers: *"If I coerce account X into authenticating, which relay attack should I chain it with, and what's the target object?"*

```
Relay Target Candidates
╭──────────────────┬─────────────┬──────────────────────────┬───────────────────────────╮
│ Account          │   Attack    │ Target Object            │ Right                     │
├──────────────────┼─────────────┼──────────────────────────┼───────────────────────────┤
│ robb.stark       │  ACLAbuse   │ Domain Root (DCSync path)│ WriteDACL                 │
│                  │  RBCD       │ CASTELBLACK$             │ WriteDACL                 │
│                  │  ShadowCreds│ CASTELBLACK$             │ WriteDACL                 │
│ Key Admins       │  ShadowCreds│ CASTELBLACK$             │ WriteProperty(msDS-Key...)│
╰──────────────────┴─────────────┴──────────────────────────┴───────────────────────────╯
```

Requires: `impacket` and `ldap3` (both available on Kali by default).

---

## Viability Logic

| Result       | Meaning                                                                     |
| ------------ | --------------------------------------------------------------------------- |
| ✅ VIABLE     | All required prerequisites met and no optional checks failed                |
| ⚠️ PARTIAL   | Required checks pass but one or more optional checks failed or were skipped |
| ❌ NOT VIABLE | At least one required check failed                                          |
| ❓ UNKNOWN    | All checks were skipped or errored                                          |

---

## External Tools Used

The checker calls these tools if installed. Gracefully falls back or skips if not found.

| Tool | Install | Used for |
|------|---------|----------|
| `nxc` / `netexec` | `apt install netexec` | SMB/LDAP/MSSQL/WebDAV checks |
| `certipy-ad` | `pip install certipy-ad` | ADCS ESC8/ESC11 detection |
| `bloodyAD` | `pip install bloodyad` | LDAP ACL/object checks |
| `impacket-GetUserSPNs` | pre-installed on Kali | MSSQL SPN enumeration |
| `impacket` (library) | pre-installed on Kali | ACL parsing (`--find-relay-targets`) |
| `ldap3` | `pip install ldap3` | Direct LDAP queries |
| `dnstool.py` | krbrelayx repo | Kerberos relay DNS check |

---

## Architecture

```
relayhound.py                    Entry point, argparse, orchestrator
ntlm_relay_checker/
├── config.py                    TargetEnv + Credential dataclasses
├── engine.py                    run_all_checks(), parallel runner,
│                                run_relay_target_finder()
├── output.py                    Rich terminal table, Markdown + HTML reports,
│                                relay target summary renderer
└── checks/
    ├── base.py                  BaseCheck, CheckResult, AttackResult, Status
    ├── smb.py                   NTLM Relay → SMB
    ├── ldap_rbcd.py             NTLM Relay → LDAP (RBCD)
    ├── ldap_shadowcreds.py      NTLM Relay → LDAP (Shadow Credentials)
    ├── adcs.py                  NTLM Relay → ADCS (ESC8)
    ├── esc11.py                 NTLM Relay → ADCS (ESC11 / RPC)
    ├── mssql.py                 NTLM Relay → MSSQL
    ├── webdav.py                NTLM Relay → HTTP/WebDAV
    ├── kerberos.py              Kerberos Relay → ADCS (krbrelayx)
    ├── laps.py                  NTLM Relay → LDAP (LAPS)
    ├── ldaps_addcomputer.py     NTLM Relay → LDAPS (Add Computer)
    ├── ldaps_aclabuse.py        NTLM Relay → LDAPS (ACL Abuse)
    └── relay_target_finder.py   Inbound ACL scan (--find-relay-targets)
```

---

## Notes

- Designed for use with a **single low-privilege domain account**
- All checks are **read-only**. No exploitation, no modifications
- WARN/SKIP checks should be verified manually
- Exit code: `0` if any attack is VIABLE/PARTIAL, `1` if none are viable
- `--find-relay-targets` requires `impacket` for `nTSecurityDescriptor` ACE parsing

## To Do List

Fix pass-the-hash support — --nt-hash flag exists as an alternative to -p but the hash is not yet passed correctly to underlying tool calls. Currently falls back to empty password, causing checks to fail.

```bash
python relayhound.py -d corp.local --dc-ip 10.10.10.1 -u lowpriv --nt-hash <nthash>
```

### Legal Disclaimer

This tool is intended for **authorised security testing and educational purposes only**.

Use of RelayHound against systems you do not own or do not have explicit written permission to test is unethical and may even be illegal. The authors accept no liability for any misuse or damage caused by this tool.
