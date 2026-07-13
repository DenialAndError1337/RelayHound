"""
LDAPS Add Computer Account prerequisite checks for NTLM Relay → LDAPS.

Relaying NTLM to LDAPS allows creating a new machine account when
MachineAccountQuota > 0. The new account can then be used for RBCD or
Shadow Credentials. Unlike plain LDAP relay, this targets LDAPS (port 636)
which bypasses LDAP signing requirements — but requires EPA to be disabled.

Prerequisites:
  [REQ]  LDAPS reachable (port 636)
  [REQ]  LDAPS channel binding (EPA) not enforced
         (LDAP signing on port 389 is irrelevant — TLS handles integrity on 636)
  [REQ]  MachineAccountQuota > 0
  [OPT]  TLS certificate valid (self-signed still works for relay)
  [OPT]  WebClient running on target (required for HTTP/WebDAV coercion path;
         not needed for mitm6 or PrinterBug/PetitPotam RPC coercion)
"""
from __future__ import annotations
import socket
import ssl
import subprocess

from .base import BaseCheck, CheckResult, Status
from ..config import TargetEnv

try:
    from ldap3 import BASE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
from ..utils import _ldap_connect, _port_open, _run_nxc_ldap, ldaps_cb_fanout, _dc_list_label


# ── helpers ────────────────────────────────────────────────────────────────


# ── individual checks ──────────────────────────────────────────────────────

class LdapsPortCheck(BaseCheck):
    """
    LDAPS must be reachable on port 636. This is the relay target —
    unlike plain LDAP relay (port 389), LDAPS bypasses the LDAP signing
    requirement since TLS provides transport-level integrity.

    Method: TCP connect to port 636 + TLS handshake attempt.
    """

    name = "LDAPS reachable (port 636)"

    def _run(self) -> CheckResult:
        if not _port_open(self.env.dc_ip, 636, timeout=self.env.timeout):
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"LDAPS port 636 not reachable on {self.env.dc_ip}. "
                    "LDAPS relay not possible — LDAPS must be enabled on the DC."
                ),
            )

        # Try TLS handshake to confirm LDAPS is functional
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self.env.dc_ip, 636), timeout=self.env.timeout
            ) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    tls_version = ssock.version()

            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"LDAPS reachable on {self.env.dc_ip}:636 "
                    f"({tls_version}). TLS handshake successful."
                ),
            )
        except ssl.SSLError as e:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"Port 636 open but TLS handshake failed: {e}. "
                    "LDAPS may still be usable for relay."
                ),
            )
        except Exception as e:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=f"Port 636 open, TLS check inconclusive: {e}",
            )


class LdapsChannelBindingCheck(BaseCheck):
    """
    LDAPS channel binding (EPA) must not be enforced.
    When set to Always, the relay tool must present a matching TLS certificate
    which is not possible in a standard relay scenario.

    Lab-confirmed 2026-07-02 (GOAD Castelblack→Winterfell): CB "When Supported"
    BLOCKS the relayed no-CBT ldaps:// bind — the relay fails at authentication
    with SEC_E_BAD_BINDINGS, not just at the write. The direct probe succeeds
    (simple/anon bind, no CBT requirement) but is not a faithful proxy for the
    relay under "When Supported". Only CB=Never (registry value 0) is relay-safe.

    Method: nxc ldap --module ldap-checker reads the registry value.
    """

    name = "LDAPS channel binding (EPA) not enforced"

    def _run(self) -> CheckResult:
        # Fan out over dc_targets(): the attacker relays to the most permissive DC,
        # so CB=Never on ANY DC is viable (a child DC with CB off is no longer missed).
        status, open_dcs, blocked_dcs, soft_dcs, unknown_dcs = ldaps_cb_fanout(self.env)
        multi = len(open_dcs) + len(blocked_dcs) + len(soft_dcs) + len(unknown_dcs) > 1

        if status is Status.PASS:
            note = ""
            if multi:
                other = blocked_dcs + soft_dcs + unknown_dcs
                note = (f" (enforced/undetermined on {_dc_list_label(self.env, other)}, "
                        "but a relay to the permissive DC still succeeds)") if other else ""
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"LDAPS channel binding NOT required (set to: Never) on "
                       f"{_dc_list_label(self.env, open_dcs)} — relay viable.{note}",
            )
        if status is Status.FAIL:
            scope = "all probed DCs" if multi else _dc_list_label(self.env, blocked_dcs)
            # ── FLIP POINT ── When Supported is treated as blocking (lab-confirmed:
            # relayed no-CBT ldaps:// bind fails with SEC_E_BAD_BINDINGS). If a future
            # lab run shows When Supported allows the relay, relax that leg in
            # utils._ldaps_cb_posture_for_dc.
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"LDAPS channel binding enforced (Always / When Supported) on {scope} "
                    "— relay blocked. A relayed no-CBT ldaps:// bind fails with "
                    "SEC_E_BAD_BINDINGS; only CB=Never (registry 0) allows the relay."
                ),
            )
        if status is Status.WARN:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"LDAPS channel binding unconfirmed on {_dc_list_label(self.env, soft_dcs)} "
                    "— a no-CBT LDAPS bind succeeded (or nxc gave no registry read), which "
                    "cannot distinguish CB=Never (relay viable) from CB=When Supported "
                    "(relay blocked). Verify LdapEnforceChannelBinding on the DC "
                    "(0=Never → viable, 1=When Supported → blocked, 2=Always → blocked)."
                ),
            )
        # SKIP: a DC could not be tested (nxc timed out / unavailable + probe
        # inconclusive) and none is confirmed open.
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Channel binding could not be determined on "
                f"{_dc_list_label(self.env, unknown_dcs)} — nxc ldap-checker timed out or is "
                "unavailable and the direct LDAPS probe was inconclusive. Manual check: "
                "LdapEnforceChannelBinding (0=Never relay viable, 1=When Supported blocked, "
                "2=Always blocked)."
            ),
        )


class MachineAccountQuotaCheck(BaseCheck):
    """
    MachineAccountQuota must be > 0 to create a new computer account via relay.
    Default is 10 in AD environments.

    Method: nxc ldap --module maq OR ldap3 query on domain root.
    """

    name = "MachineAccountQuota > 0 (can create computer accounts)"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "maq"], self.env)
        combined = out + err
        if rc != -1:
            import re
            m = re.search(r"MachineAccountQuota[:\s]+(\d+)", combined, re.IGNORECASE)
            if m:
                maq = int(m.group(1))
                if maq > 0:
                    return CheckResult(
                        name=self.name, status=Status.PASS,
                        detail=(
                            f"ms-DS-MachineAccountQuota = {maq}. "
                            "Any domain user can create up to this many computer accounts. "
                            "Relay → LDAPS → create machine account → use for RBCD/Shadow Creds."
                        ),
                    )
                return CheckResult(
                    name=self.name, status=Status.FAIL,
                    detail=(
                        "ms-DS-MachineAccountQuota = 0. "
                        "Cannot create new computer accounts as a low-privilege user. "
                        "LDAPS relay still useful for ACL abuse if relayed account "
                        "has WriteDACL/GenericAll on existing objects."
                    ),
                )

        if not LDAP3_AVAILABLE:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="ldap3 not installed.")

        conn = _ldap_connect(self.env)
        if not conn:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAP connection failed.")
        try:
            import re
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
                    name=self.name, status=Status.FAIL,
                    detail="ms-DS-MachineAccountQuota = 0.",
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
                           detail="Could not read MAQ.")


class LdapsTlsCertCheck(BaseCheck):
    """
    Optional: verify whether the DC's LDAPS certificate is self-signed or CA-issued.
    Self-signed certs still allow relay — just informational.
    """

    name = "LDAPS TLS certificate info (informational)"
    required = False

    def _run(self) -> CheckResult:
        if not _port_open(self.env.dc_ip, 636, timeout=self.env.timeout):
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail="LDAPS port not reachable.")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self.env.dc_ip, 636), timeout=self.env.timeout
            ) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    tls_ver = ssock.version()
                    cipher = ssock.cipher()
                    # getpeercert() returns empty dict with CERT_NONE;
                    # use binary form to check if cert is self-signed
                    cert_der = ssock.getpeercert(binary_form=True)

            self_signed = False
            cn = "N/A"
            if cert_der:
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                    subject_cn = cert_obj.subject.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME)
                    cn = subject_cn[0].value if subject_cn else "N/A"
                    self_signed = cert_obj.subject == cert_obj.issuer
                except ImportError:
                    # cryptography library not installed — report basic info only
                    pass

            cipher_str = f"{cipher[0]}" if cipher else "unknown cipher"
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=(
                    f"LDAPS cert: CN={cn}, "
                    f"TLS={tls_ver}, Cipher={cipher_str}, "
                    f"Self-signed={'yes' if self_signed else 'no/unknown'}. "
                    "Self-signed certs are fine for relay — no cert validation needed."
                ),
            )
        except Exception as e:
            return CheckResult(name=self.name, status=Status.SKIP,
                               detail=f"Could not read TLS cert: {e}")


class LdapsWebClientCheck(BaseCheck):
    """
    Optional: WebClient service running on target enables HTTP/WebDAV coercion
    to force a machine account to authenticate for LDAPS relay.

    Only required if using PetitPotam HTTP coercion as the trigger.
    Not required for:
      - mitm6 (poisons DHCPv6/DNS — no WebClient needed)
      - PrinterBug (RPC-based — no WebClient needed)
      - PetitPotam SMB coercion (RPC-based — no WebClient needed)
    """

    name = "WebClient running on target (needed for HTTP coercion path)"
    required = False

    def _run(self) -> CheckResult:
        webclient_hosts = []
        for host in self.env.all_targets:
            try:
                result = subprocess.run(
                    ["nxc", "smb", host,
                     "-u", self.env.cred.username,
                     *((["-H", self.env.cred.nt_hash] if self.env.cred.nt_hash else ["-p", self.env.cred.password])),
                     "-d", self.env.domain,
                     "--module", "webdav"],
                    capture_output=True, text=True,
                    timeout=self.env.timeout + 10,
                )
                combined = (result.stdout + result.stderr).lower()
                if result.returncode != -1 and (
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
                    "HTTP coercion (PetitPotam HTTP) viable for LDAPS relay trigger. "
                    "mitm6 and PrinterBug coercion work regardless of WebClient."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail=(
                "WebClient not confirmed on targets — HTTP coercion path unavailable. "
                "Use mitm6, PrinterBug, or PetitPotam RPC coercion instead."
            ),
        )


# ── attack check list ──────────────────────────────────────────────────────

def get_checks(env: TargetEnv) -> list[BaseCheck]:
    return [
        LdapsPortCheck(env),
        LdapsChannelBindingCheck(env),
        MachineAccountQuotaCheck(env),
        LdapsTlsCertCheck(env),
        LdapsWebClientCheck(env),
    ]

ATTACK_NAME = "NTLM Relay → LDAPS (Add Computer Account)"
