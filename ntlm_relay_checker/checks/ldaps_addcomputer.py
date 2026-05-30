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
    import ldap3
    from ldap3 import Server, Connection, NTLM, BASE, ALL
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


# ── helpers ────────────────────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: int = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


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


def _ldap_connect(env: TargetEnv):
    if not LDAP3_AVAILABLE:
        return None
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        conn = Connection(
            server,
            user=env.cred.upn,
            password=env.cred.password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn
    except Exception:
        return None


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
                    cert = ssock.getpeercert(binary_form=True)
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

    When set to Never or When Supported (default): relay viable.

    Method: nxc ldap --module ldap-checker reads the registry value.
    """

    name = "LDAPS channel binding (EPA) not enforced"

    def _run(self) -> CheckResult:
        rc, out, err = _run_nxc_ldap(["--module", "ldap-checker"], self.env)
        combined = (out + err).lower()

        if rc == -1:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail=(
                    "nxc not available. "
                    "Manual check: LdapEnforceChannelBinding registry value on DC. "
                    "0=Never, 1=When Supported, 2=Always (blocks relay)."
                ),
            )

        if "channel binding is set to: never" in combined or "channel binding is not required" in combined:
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail="LDAPS channel binding NOT required (set to: Never) — relay viable.",
            )
        if "channel binding is set to: always" in combined or "channel binding is required" in combined:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    "LDAPS channel binding REQUIRED (set to: Always). "
                    "Relay blocked — attacker cannot present matching TLS cert."
                ),
            )
        if "channel binding is set to: when supported" in combined:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    "LDAPS channel binding set to: When Supported. "
                    "Relay may work — depends on whether client signals EPA support."
                ),
            )
        return CheckResult(
            name=self.name, status=Status.WARN,
            detail="Channel binding status unclear. Review manually.",
            raw=(out + err)[:300],
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
                    issuer_cn = cert_obj.issuer.get_attributes_for_oid(
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
