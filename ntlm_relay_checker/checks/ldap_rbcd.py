"""
RBCD prerequisite checks for NTLM Relay → LDAP (Resource-Based Constrained Delegation).

RBCD allows a relayed machine account to be granted delegation rights over
another computer object by writing to msDS-AllowedToActOnBehalfOfOtherIdentity.
The attacker-controlled machine account can then impersonate any user to the
target service via S4U2Self + S4U2Proxy.

Prerequisites:
  [REQ]  LDAP signing not enforced
  [REQ]  LDAP channel binding not required
  [REQ]  Domain functional level ≥ 2012 (msDS-AllowedToActOnBehalfOfOtherIdentity
         was introduced in Windows Server 2012 / DFL 5)
  [REQ]  Writable computer object exists — the RBCD target; relay writes
         msDS-AllowedToActOnBehalfOfOtherIdentity on this object
  [REQ*] MachineAccountQuota > 0 — needed to create the attacker-controlled
         machine account used as the delegation principal. Soft blocker:
         MAQ = 0 is bypassed if the attacker already controls an existing
         machine account in the domain (checked separately; marked WARN
         rather than FAIL so viability is not wrongly blocked)
  [OPT]  WebClient running on target (HTTP coercion path via PetitPotam)
         Not needed for mitm6 or PrinterBug/PetitPotam RPC coercion
"""
from __future__ import annotations
import re
import subprocess
from typing import Optional

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, BASE, SUBTREE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


# ── helpers ────────────────────────────────────────────────────────────────

def _ldap_connect(env: TargetEnv) -> Optional[object]:
    if not LDAP3_AVAILABLE:
        return None
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        # ldap3 NTLM accepts NT hash as "LMHASH:NTHASH" in the password field.
        # Use the empty LM hash prefix when only the NT hash is supplied.
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]  # strip LM: prefix if present
            auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
        else:
            auth_password = env.cred.password
        conn = Connection(
            server,
            user=env.cred.upn,
            password=auth_password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn
    except Exception:
        return None


def _run_bloodyad(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]
            auth = ["--dc-ip", env.dc_ip, "-p", f":{nh}"]
        else:
            auth = ["-p", env.cred.password]
        cmd = ["bloodyAD", "--host", env.dc_ip,
               "-d", env.domain,
               "-u", env.cred.username] + auth + args
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", "bloodyAD not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _run_nxc_ldap(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    try:
        auth = (["-H", env.cred.nt_hash] if env.cred.nt_hash
                else ["-p", env.cred.password])
        cmd = ["nxc", "ldap", env.dc_ip,
               "-u", env.cred.username,
               "-d", env.domain] + auth + args
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        try:
            cmd[0] = "crackmapexec"
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "nxc not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


# ── individual checks ──────────────────────────────────────────────────────

class LdapSigningCheck(BaseCheck):
    """LDAP signing must not be enforced for relay to succeed."""

    name = "LDAP signing not enforced"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "ldap-checker"], self.env)
        combined = (out + err).lower()

        if rc != -1:
            if "ldap signing not enforced" in combined or "signing: false" in combined:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="LDAP signing NOT enforced — relay to LDAP viable.",
                )
            if "ldap signing enforced" in combined or "signing: true" in combined:
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail="LDAP signing REQUIRED (LdapServerIntegrity=2) — relay rejected.",
                )

        if LDAP3_AVAILABLE:
            try:
                from ldap3 import ANONYMOUS
                server = Server(self.env.dc_ip, connect_timeout=self.env.timeout)
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
                if conn.bound:
                    conn.unbind()
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail="Anonymous LDAP bind succeeded — signing not enforced.",
                    )
            except Exception as e:
                if "stronger" in str(e).lower() or "sign" in str(e).lower():
                    return CheckResult(
                        name=self.name, status=Status.FAIL,
                        detail=f"LDAP requires signing: {e}",
                    )

        return CheckResult(name=self.name, status=Status.SKIP,
                           detail="Could not determine LDAP signing status.")


class LdapChannelBindingCheck(BaseCheck):
    """LDAP channel binding must not be required."""

    name = "LDAP channel binding not required"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "ldap-checker"], self.env)
        combined = (out + err).lower()

        if rc == -1:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="nxc not available to check channel binding.")

        if "channel binding is set to: never" in combined or "channel binding is not required" in combined:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="LDAP channel binding NOT required (set to: Never) — relay viable.",
            )
        if "channel binding is set to: always" in combined or "channel binding is required" in combined:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail="LDAP channel binding REQUIRED — relay blocked.",
            )
        if "channel binding is set to: when supported" in combined:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail="Channel binding set to: When Supported — relay may work.",
            )
        return CheckResult(name=self.name, status=Status.WARN,
                           detail="Channel binding status unclear. Review manually.")


class DomainFunctionalLevelCheck(BaseCheck):
    """
    RBCD requires DFL ≥ 5 (Windows Server 2012).
    msDS-AllowedToActOnBehalfOfOtherIdentity was introduced in Windows
    Server 2012 (not 2012 R2 — DFL 5 is sufficient). Below this level
    the attribute does not exist and relay will fail silently.

    Old environments (DFL 2008 or lower) are encountered in practice —
    do not assume this check will always pass.

    Method: ldap3 query msDS-Behavior-Version on domain root.
    """

    name = "Domain functional level ≥ 2012 (RBCD support)"

    DFL_NAMES = {
        0: "2000", 1: "2003 Mixed", 2: "2003", 3: "2008",
        4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016+",
    }

    def _run(self) -> CheckResult:
        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed.")
        conn = _ldap_connect(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed.")
        try:
            domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
            conn.search(
                search_base=domain_dn,
                search_filter="(objectClass=domain)",
                search_scope=BASE,
                attributes=["msDS-Behavior-Version"],
            )
            if conn.entries:
                dfl = int(conn.entries[0]["msDS-Behavior-Version"].value or 0)
                dfl_name = self.DFL_NAMES.get(dfl, f"unknown ({dfl})")
                if dfl >= 5:
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=(
                            f"DFL = {dfl} (Windows Server {dfl_name}). "
                            "msDS-AllowedToActOnBehalfOfOtherIdentity supported — RBCD viable."
                        ),
                    )
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"DFL = {dfl} (Windows Server {dfl_name}). "
                        "RBCD requires DFL ≥ 5 (Windows Server 2012). "
                        "msDS-AllowedToActOnBehalfOfOtherIdentity attribute not available at this level."
                    ),
                )
        except Exception as e:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"LDAP query failed: {e}")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
        return CheckResult(name=self.name, status=Status.SKIP,
                           detail="Could not read DFL.")


class MachineAccountQuotaCheck(BaseCheck):
    """
    MAQ > 0 allows ntlmrelayx to create an attacker-controlled machine account
    for use as the RBCD delegation principal.

    MAQ = 0 is a soft blocker — RBCD is still viable if the attacker already
    controls an existing machine account in the domain. For this reason the
    check is required=False: MAQ = 0 produces WARN (not FAIL) so the attack
    is not wrongly marked NOT VIABLE when an existing machine account may be
    available. The writable computer object (the RBCD target) is the hard
    requirement checked separately by WritableComputerObjectCheck.
    """

    name = "MachineAccountQuota > 0 (create attacker-controlled machine account)"
    required = False

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "maq"], self.env)
        combined = out + err

        if rc != -1:
            m = re.search(r"MachineAccountQuota[:\s]+(\d+)", combined, re.IGNORECASE)
            if m:
                maq = int(m.group(1))
                if maq > 0:
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=(
                            f"ms-DS-MachineAccountQuota = {maq}. "
                            "ntlmrelayx can create an attacker-controlled machine account "
                            "for use as the RBCD delegation principal."
                        ),
                    )
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "ms-DS-MachineAccountQuota = 0 — ntlmrelayx cannot create a new "
                        "machine account automatically. RBCD is still viable if you already "
                        "control an existing machine account: pass it to ntlmrelayx via "
                        "--escalate-user or use it as the delegation principal manually."
                    ),
                )

        if LDAP3_AVAILABLE:
            conn = _ldap_connect(self.env)
            if conn:
                try:
                    domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
                    conn.search(
                        search_base=domain_dn,
                        search_filter="(objectClass=domain)",
                        search_scope=BASE,
                        attributes=["ms-DS-MachineAccountQuota"],
                    )
                    if conn.entries:
                        maq = int(conn.entries[0]["ms-DS-MachineAccountQuota"].value or 0)
                        conn.unbind()
                        if maq > 0:
                            return CheckResult(
                                name=self.name, status=Status.PASS,
                                detail=f"ms-DS-MachineAccountQuota = {maq}.",
                            )
                        return CheckResult(
                            name=self.name, status=Status.WARN,
                            detail=(
                                "ms-DS-MachineAccountQuota = 0 — ntlmrelayx cannot create "
                                "a new machine account automatically. RBCD is still viable "
                                "if you already control an existing machine account."
                            ),
                        )
                except Exception as e:
                    return CheckResult(name=self.name, status=Status.SKIP,
                                       detail=f"LDAP query failed: {e}")
                finally:
                    try:
                        conn.unbind()
                    except Exception:
                        pass

        return CheckResult(name=self.name, status=Status.SKIP,
                           detail="Could not read MAQ. Install nxc or ldap3.")


class WritableComputerObjectCheck(BaseCheck):
    """
    A writable computer object must exist for RBCD.
    The relayed machine account writes its own SID into
    msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer.

    Method: bloodyAD get writable --otype COMPUTER
    """

    name = "Writable computer object exists (msDS-AllowedToActOnBehalfOfOtherIdentity)"

    def _run(self) -> CheckResult:
        rc, out, err = _run_bloodyad(
            ["get", "writable", "--otype", "COMPUTER"], self.env
        )
        if rc == 0:
            if out.strip():
                computers = re.findall(r"CN=([^,$\n]+)", out)
                computers = [c.strip() for c in computers
                             if c.strip()
                             and c.strip().lower() not in ("computers", "users", "domain controllers")][:5]
                display = ", ".join(computers) if computers else out[:150].strip()
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"Writable computer object(s): {display}. "
                        "Relay can write msDS-AllowedToActOnBehalfOfOtherIdentity "
                        "on these targets for RBCD."
                    ),
                    raw=out[:400],
                )
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "No writable computer objects found for this account. "
                    "RBCD requires GenericWrite or WriteDACL on a computer object "
                    "to write msDS-AllowedToActOnBehalfOfOtherIdentity (the RBCD target). "
                    "Note: this is separate from MAQ — a machine account to act as the "
                    "delegation principal is also needed (see MachineAccountQuota check). "
                    "A higher-privileged relayed account may have write access."
                ),
            )

        if LDAP3_AVAILABLE:
            conn = _ldap_connect(self.env)
            if conn:
                try:
                    domain_dn = ",".join(f"DC={p}" for p in self.env.domain.split("."))
                    conn.search(
                        search_base=domain_dn,
                        search_filter="(objectClass=computer)",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName"],
                        paged_size=10,
                    )
                    computers = [str(e["sAMAccountName"]) for e in conn.entries]
                    if computers:
                        return CheckResult(
                            name=self.name, status=Status.WARN,
                            detail=(
                                f"Found {len(computers)} computer object(s): "
                                f"{', '.join(computers[:5])}. "
                                "Verify write access manually: "
                                "`bloodyAD get writable --otype COMPUTER`"
                            ),
                        )
                except Exception:
                    pass
                finally:
                    try:
                        conn.unbind()
                    except Exception:
                        pass

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail="Could not check writable objects. Install bloodyAD: pip install bloodyad",
        )


class WebClientCoercionCheck(BaseCheck):
    """
    Optional: WebClient running on target enables HTTP coercion (PetitPotam HTTP).
    Not required for mitm6, PrinterBug, or PetitPotam RPC coercion.
    """

    name = "WebClient running on target (HTTP coercion path)"
    required = False

    def _run(self) -> CheckResult:
        webclient_hosts = []
        for host in self.env.all_targets:
            try:
                r = subprocess.run(
                    ["nxc", "smb", host,
                     "-u", self.env.cred.username,
                     *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                     "-d", self.env.domain,
                     "--module", "webdav"],
                    capture_output=True, text=True,
                    timeout=self.env.timeout + 10,
                )
                combined = (r.stdout + r.stderr).lower()
                if r.returncode != -1 and (
                    "webclient service enabled" in combined or
                    "webdav: true" in combined or
                    "running" in combined
                ):
                    webclient_hosts.append(host)
            except Exception:
                pass

        if webclient_hosts:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"WebClient running on: {', '.join(webclient_hosts)}. "
                    "HTTP coercion (PetitPotam HTTP) available. "
                    "mitm6 and PrinterBug coercion work regardless of WebClient."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "WebClient not confirmed — HTTP coercion path unavailable. "
                "Use mitm6 (no WebClient needed), PrinterBug, "
                "or PetitPotam RPC coercion instead."
            ),
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        LdapSigningCheck(env),
        LdapChannelBindingCheck(env),
        DomainFunctionalLevelCheck(env),
        MachineAccountQuotaCheck(env),
        WritableComputerObjectCheck(env),
        WebClientCoercionCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAP (RBCD)"
