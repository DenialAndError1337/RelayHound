"""
Shadow Credentials prerequisite checks for NTLM Relay → LDAP (Shadow Credentials).

Shadow Credentials abuses the msDS-KeyCredentialLink attribute to add an
attacker-controlled certificate credential to a computer or user object.
The victim can then be authenticated using PKINIT with the certificate,
and UnPAC-the-hash recovers the NT hash without requiring ADCS relay.

Prerequisites:
  [REQ]  LDAP signing not enforced
  [REQ]  LDAP channel binding not required
  [REQ]  Domain functional level ≥ 2016 (msDS-KeyCredentialLink support)
  [REQ]  Writable computer/user object exists
         (write access to msDS-KeyCredentialLink)
  [REQ]  DC has a KDC certificate (PKINIT must be functional for the relay
         to yield anything usable — writing msDS-KeyCredentialLink without
         a working PKINIT path produces no exploitable result)
  [OPT]  ADCS present (needed for UnPAC-the-hash NT hash recovery;
         not required — attack still yields a TGT without ADCS)
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


def _run_certipy(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["certipy-ad"] + args, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        try:
            r = subprocess.run(["certipy"] + args, capture_output=True,
                               text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "certipy-ad not found"
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
    Shadow Credentials require DFL ≥ 7 (Windows Server 2016).
    The msDS-KeyCredentialLink attribute was introduced in 2016.
    Below this level the attribute doesn't exist and relay will fail.

    Method: ldap3 query msDS-Behavior-Version on domain root.
    """

    name = "Domain functional level ≥ 2016 (msDS-KeyCredentialLink support)"

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
                name = self.DFL_NAMES.get(dfl, f"unknown ({dfl})")
                if dfl >= 7:
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=(
                            f"DFL = {dfl} (Windows Server {name}). "
                            "msDS-KeyCredentialLink supported — Shadow Credentials viable."
                        ),
                    )
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        f"DFL = {dfl} (Windows Server {name}). "
                        "Shadow Credentials require DFL ≥ 7 (2016). "
                        "msDS-KeyCredentialLink attribute not available at this level."
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


class WritableKeyCredentialLinkCheck(BaseCheck):
    """
    A writable computer or user object must exist for Shadow Credentials.
    The relayed account writes an attacker-controlled certificate into
    msDS-KeyCredentialLink on the target object.

    Method: bloodyAD get writable --otype COMPUTER
            (user objects also valid but computer accounts are the primary target)
    """

    name = "Writable object exists (msDS-KeyCredentialLink)"

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
                        "Relay can write msDS-KeyCredentialLink on these targets "
                        "for Shadow Credentials."
                    ),
                    raw=out[:400],
                )
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "No writable computer objects found for this account. "
                    "Shadow Credentials requires GenericWrite or WriteDACL "
                    "on a computer or user object. "
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


class AdcsForPkinitCheck(BaseCheck):
    """
    Optional: ADCS present for PKINIT/UnPAC-the-hash follow-up.
    Shadow Credentials gives a TGT via PKINIT. To recover the NT hash
    (UnPAC-the-hash), ADCS is needed. Without ADCS you still get a TGT
    but cannot easily recover the hash.

    Method: nxc ldap --module adcs + certipy find.
    """

    name = "ADCS present for PKINIT/UnPAC-the-hash follow-up"
    required = False

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "adcs"], self.env)
        combined = out + err
        lower = combined.lower()

        if rc != -1 and combined.strip():
            if "nosuchobject" in lower or ("unexpected exception" in lower and "enrollment" in lower):
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No ADCS found in this domain. "
                        "Shadow Credentials still gives a TGT via PKINIT, "
                        "but UnPAC-the-hash (NT hash recovery) requires ADCS. "
                        "Check parent/sibling domains for a CA."
                    ),
                )
            ca_names = re.findall(r"Found CN:[\s]*([^\s\n\r]+)", combined, re.IGNORECASE)
            if ca_names:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        f"ADCS found: CA {', '.join(ca_names[:2])}. "
                        "Full attack chain: Shadow Creds → PKINIT TGT → "
                        "UnPAC-the-hash → NT hash → pass-the-hash."
                    ),
                )

        # Fallback: certipy
        rc2, out2, err2 = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ])
        if rc2 != -1:
            combined2 = (out2 + err2).lower()
            if "certificate authorit" in combined2 or "ca name" in combined2:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail="ADCS CA found via certipy — UnPAC-the-hash follow-up viable.",
                )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not confirm ADCS presence. "
                "Run: `certipy-ad find -u <user>@<domain> -p <pass> -dc-ip <dc> -stdout`"
            ),
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
                else:
                    # Fallback: check via --services if --module webdav was ambiguous
                    r2 = subprocess.run(
                        ["nxc", "smb", host,
                         "-u", self.env.cred.username,
                         *(([ "-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                         "-d", self.env.domain,
                         "--services"],
                        capture_output=True, text=True,
                        timeout=self.env.timeout + 10,
                    )
                    combined2 = (r2.stdout + r2.stderr).lower()
                    if "webclient" in combined2 and ("running" in combined2 or "started" in combined2):
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



class DcKdcCertificateCheck(BaseCheck):
    """
    The DC must have a KDC certificate to support PKINIT authentication.
    Shadow Credentials writes a certificate credential to msDS-KeyCredentialLink,
    then uses PKINIT to authenticate as the target using that certificate.
    If the DC has no KDC certificate, PKINIT will fail even with valid Shadow Creds.

    In practice this is satisfied by:
      - ADCS deployed (DC auto-enrolls for KDC Authentication template)
      - Any other CA that has issued a KDC certificate to the DC

    Method: certipy find — look for KDC Authentication or Domain Controller
            templates issued to DC machine accounts.
            Fallback: confirm ADCS is present (strong indicator KDC cert exists).
    """

    name = "DC has KDC certificate for PKINIT (Shadow Credentials delivery)"

    def _run(self) -> CheckResult:
        # certipy find — check for KDC Authentication template
        rc, out, err = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ])

        if rc != -1:
            combined = out + err
            lower = combined.lower()
            # KDC Authentication or Domain Controller template = DC has/can get KDC cert
            if "kdc authentication" in lower or "domaincontroller" in lower.replace(" ", ""):
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        "KDC Authentication or DomainController certificate template found. "
                        "DC can obtain a KDC certificate — PKINIT authentication viable. "
                        "Shadow Credentials → PKINIT TGT → UnPAC-the-hash will work."
                    ),
                )
            if "certificate authorit" in lower or "ca name" in lower:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "ADCS present but KDC Authentication template not explicitly confirmed. "
                        "DC likely has a KDC certificate via auto-enrollment. "
                        "Verify: check if DC has a certificate with KDC EKU "
                        "(1.3.6.1.5.2.3.5) using `certipy find -stdout`."
                    ),
                )
            else:
                # certipy ran successfully but found no CA or KDC template
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No ADCS or KDC certificate template found via certipy. "
                        "Without a KDC certificate on the DC, PKINIT will fail and "
                        "Shadow Credentials cannot be used to obtain a TGT. "
                        "If a third-party CA is in use, verify manually."
                    ),
                )

        # Fallback: check ADCS via nxc
        try:
            import subprocess
            r = subprocess.run(
                ["nxc", "ldap", self.env.dc_ip,
                 "-u", self.env.cred.username,
                 *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                 "-d", self.env.domain,
                 "--module", "adcs"],
                capture_output=True, text=True, timeout=20,
            )
            combined = (r.stdout + r.stderr).lower()
            if "found cn" in combined or "found pki" in combined:
                return CheckResult(
                    name=self.name, status=Status.PASS,
                    detail=(
                        "ADCS detected — DC almost certainly has a KDC certificate "
                        "via auto-enrollment. PKINIT authentication viable."
                    ),
                )
            if "nosuchobject" in combined:
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "No ADCS in this domain. Check parent/sibling domain for a CA. "
                        "DC needs a KDC certificate for PKINIT to work with Shadow Credentials."
                    ),
                )
        except Exception:
            pass

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not verify KDC certificate status. "
                "Install certipy-ad: pip install certipy-ad"
            ),
        )

# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        LdapSigningCheck(env),
        LdapChannelBindingCheck(env),
        DomainFunctionalLevelCheck(env),
        WritableKeyCredentialLinkCheck(env),
        DcKdcCertificateCheck(env),
        AdcsForPkinitCheck(env),
        WebClientCoercionCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAP (Shadow Credentials)"
