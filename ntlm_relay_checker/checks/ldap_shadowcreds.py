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

from .base import BaseCheck, CheckResult, Status, ldap_or_relay_viability
from ..config import TargetEnv
from .relay_target_finder import relay_target_principals_note

try:
    from ldap3 import BASE, SUBTREE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from ..utils import (LdapSigningCheck, LdapChannelBindingCheck,
                     _ldap_connect_with_tls_fallback,
                     _run_bloodyad, _run_certipy, _run_nxc_ldap,
                     _certipy_ca_present, _certipy_enumerated, adcs_enrollment_verdict)


# ── helpers ────────────────────────────────────────────────────────────────


# ── individual checks ──────────────────────────────────────────────────────

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
        conn, _via_tls = _ldap_connect_with_tls_fallback(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed (tried plain and TLS).")
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
    # Optional/informational: probes the OPERATOR's current write rights. Shadow
    # Credentials is carried out via the relayed victim's rights, so "not writable
    # by me" must NOT make the attack NOT VIABLE — viability is driven by the
    # protocol prerequisites (LDAP signing / channel binding / DFL / KDC cert) above.
    required = False

    def _run(self) -> CheckResult:
        result = self._run_base()
        note = relay_target_principals_note(self.env, "ShadowCreds")
        if note:
            result.detail = (result.detail or "") + note
        return result

    def _run_base(self) -> CheckResult:
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
                        "Your current account can already write these — you can perform Shadow "
                        "Credentials directly (write msDS-KeyCredentialLink), no relay needed "
                        "for these. Relay a more privileged victim only for objects outside "
                        "your current write rights."
                    ),
                    raw=out[:400],
                )
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "No writable computer objects found for this account. "
                    "Does not block the attack — Shadow Credentials requires GenericWrite "
                    "or WriteDACL on a computer or user object. "
                    "A higher-privileged relayed account may have write access."
                ),
            )

        if LDAP3_AVAILABLE:
            conn, _via_tls = _ldap_connect_with_tls_fallback(self.env)
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
    Optional: ADCS present for the PKINIT / UnPAC-the-hash follow-up.
    Shadow Credentials delivers via PKINIT, and PKINIT needs the KDC to hold a
    KDC certificate — which only an Enterprise CA issues. So without ADCS the
    PKINIT step fails outright (no TGT at all; lab-confirmed —
    KDC_ERR_PADATA_TYPE_NOSUPP), not merely the UnPAC-the-hash recovery. With
    ADCS the full chain works: Shadow Creds → PKINIT TGT → UnPAC-the-hash.

    Authoritative source is the shared adcs_enrollment_verdict() (RootDSE-based,
    child-domain safe); nxc/certipy are positive-only enrichment on the
    inconclusive path.
    """

    name = "ADCS present for PKINIT/UnPAC-the-hash follow-up"
    required = False

    def _run(self) -> CheckResult:
        # Authoritative, child-domain-safe ADCS presence (RootDSE-based).
        v = adcs_enrollment_verdict(self.env)
        if v.status == Status.FAIL:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "No Enterprise CA in the forest. PKINIT needs the KDC to hold "
                    "a KDC certificate (only an Enterprise CA issues one), so the "
                    "Shadow Credentials → PKINIT step fails outright — no TGT, and "
                    "therefore no UnPAC-the-hash either (lab-confirmed: KDC rejects "
                    "the PKINIT AS-REQ with KDC_ERR_PADATA_TYPE_NOSUPP). Rare "
                    "exception: a DC issued a KDC cert by a third-party/standalone "
                    "PKI outside AD CS would still support PKINIT."
                ),
            )
        if v.status == Status.PASS:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    "Enterprise CA present — full chain viable: Shadow Creds → "
                    "PKINIT TGT → UnPAC-the-hash → NT hash → pass-the-hash."
                ),
            )

        # LDAP inconclusive (e.g. bind refused) → positive-only enrichment.
        # nxc noSuchObject is NOT treated as FAIL: nxc string-builds the config
        # NC from the domain, so it false-negatives in child domains.
        rc, out, err = _run_nxc_ldap(["--module", "adcs"], self.env)
        combined = out + err
        if rc != -1 and combined.strip():
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

        rc2, out2, err2 = _run_certipy([
            "find",
            "-u", f"{self.env.cred.username}@{self.env.domain}",
            *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
            "-dc-ip", self.env.dc_ip,
            "-stdout",
        ])
        if rc2 != -1 and _certipy_ca_present((out2 + err2).lower()):
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="ADCS CA found via certipy — full PKINIT/UnPAC chain viable.",
            )

        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not confirm ADCS presence (LDAP probe inconclusive). "
                "Run: `certipy-ad find -u <user>@<domain> -p <pass> -dc-ip <dc> -ldap-scheme ldap -stdout`"
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
            if _certipy_ca_present(lower):
                return CheckResult(
                    name=self.name, status=Status.WARN,
                    detail=(
                        "ADCS present but KDC Authentication template not explicitly confirmed. "
                        "DC likely has a KDC certificate via auto-enrollment. "
                        "Verify: check if DC has a certificate with KDC EKU "
                        "(1.3.6.1.5.2.3.5) using `certipy find -stdout`."
                    ),
                )
            if _certipy_enumerated(lower):
                # certipy enumerated the directory and found no CA / KDC template
                # → the DC genuinely has no KDC-certificate path.
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "No ADCS or KDC certificate template found via certipy. "
                        "Without a KDC certificate on the DC, PKINIT will fail and "
                        "Shadow Credentials cannot be used to obtain a TGT. "
                        "If a third-party CA is in use, verify manually."
                    ),
                )
            # certipy ran but never enumerated (connection error / unreachable DC):
            # its "no CA" is not evidence of absence. Fall through to the
            # authoritative LDAP probe below, which SKIPs on an unreachable DC
            # instead of returning a false FAIL.

        # Fallback (certipy unavailable): authoritative LDAP probe. Use the
        # shared verdict rather than nxc's adcs module — the helper reads the
        # forest-root Configuration NC from RootDSE, so it's correct in child
        # domains, whereas nxc string-builds the config NC from the domain name
        # and returns a spurious noSuchObject in children (which would otherwise
        # become a false FAIL here).
        v = adcs_enrollment_verdict(self.env)
        if v.status == Status.FAIL:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "No Enterprise CA in the forest, so the DC has no KDC "
                    "certificate and PKINIT is unavailable — Shadow Credentials "
                    "cannot obtain a TGT (the KDC rejects the PKINIT AS-REQ with "
                    "KDC_ERR_PADATA_TYPE_NOSUPP; lab-confirmed). Rare exception: a "
                    "DC issued a KDC certificate by a third-party/standalone PKI "
                    "(outside AD CS) would still support PKINIT despite no "
                    "Enterprise CA being registered in the directory."
                ),
            )
        if v.status == Status.PASS:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "Enterprise CA present — the DC almost certainly has a KDC "
                    "certificate via auto-enrollment, so PKINIT is viable. (The "
                    "KDC Authentication template was not individually confirmed on "
                    "this path; install certipy-ad for template-level detail.)"
                ),
            )

        # Distinguish "certipy binary absent" from "certipy ran but couldn't
        # enumerate" (e.g. DC unreachable / timed out) — rc == -1 is returned
        # ONLY when the binary is missing. Reusing the "install certipy-ad"
        # wording for a timeout misattributed the cause (seen in GOAD
        # sc-unreachable: Certipy v5 ran and timed out, yet the detail said
        # "not available").
        if rc == -1:
            skip_detail = (
                "Could not verify KDC certificate status (LDAP probe inconclusive "
                "and certipy-ad not installed). Install certipy-ad: pip install certipy-ad"
            )
        else:
            skip_detail = (
                "Could not verify KDC certificate status — certipy ran but did not "
                "enumerate (DC unreachable / timed out) and the LDAP probe was also "
                "inconclusive. Re-run against a reachable DC to confirm."
            )
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=skip_detail,
        )

# ── attack check list ──────────────────────────────────────────────────────

# OR relay-path verdict (signing OR channel-binding OR NTLMv1). Attached by the
# engine via AttackResult.viability_fn.
module_viability = ldap_or_relay_viability


def get_checks(env: TargetEnv) -> list[BaseCheck]:
    from ..utils import NtlmV1AuthProbeCheck
    return [
        LdapSigningCheck(env),
        LdapChannelBindingCheck(env),
        DomainFunctionalLevelCheck(env),
        WritableKeyCredentialLinkCheck(env),
        DcKdcCertificateCheck(env),
        AdcsForPkinitCheck(env),
        WebClientCoercionCheck(env),
        NtlmV1AuthProbeCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAP (Shadow Credentials)"
