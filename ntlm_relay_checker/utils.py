"""
Shared helpers and reusable check classes for RelayHound modules.

Candidates for future consolidation here:
  - _run_nxc_ldap   (duplicated in ldap_rbcd, ldap_shadowcreds, adcs, laps, ...)
  - _ldap_connect   (duplicated in ldap_rbcd, ldap_shadowcreds, laps, ...)
  - _port_open      (duplicated in kerberos, adcs, esc11, ...)
  - _http_get       (duplicated in kerberos, adcs, webdav, ...)
  - _run_bloodyad   (duplicated in ldap_rbcd, ldap_shadowcreds, laps, ...)
  - _dns_srv_ips    (duplicated in smb, startup)
  - EnrollableTemplateCheck (duplicated in adcs, esc11)
"""
from __future__ import annotations
import subprocess
from dataclasses import dataclass

from .checks.base import BaseCheck, CheckResult, Status
from .config import TargetEnv


# ── internal helpers ────────────────────────────────────────────────────────

def _run_nxc_smb(args: list[str], env: TargetEnv, timeout: int = 30) -> tuple[int, str, str]:
    """Run `nxc smb <args>`, falling back to crackmapexec. Returns (rc, stdout, stderr)."""
    try:
        cmd = ["nxc", "smb"] + args
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


# ── coerce_plus result dataclass ─────────────────────────────────────────────

@dataclass
class CoercePlusResult:
    """Per-host result from coerce_plus."""
    host: str
    printerbug:   bool = False
    petitpotam:   bool = False
    dfscoerce:    bool = False
    shadowcoerce: bool = False
    mseven:       bool = False
    tool_unavailable: bool = False   # nxc binary not present at all
    errored:      bool = False       # probe could not complete (timeout/other) — status unknown
    raw_output:   str  = ""

    @property
    def any_method(self) -> bool:
        return any([self.printerbug, self.petitpotam,
                    self.dfscoerce, self.shadowcoerce, self.mseven])

    def method_summary(self) -> str:
        """Return a compact per-method status string, e.g. 'PrinterBug ✓  PetitPotam ✗ ...'"""
        methods = [
            ("PrinterBug",   self.printerbug),
            ("PetitPotam",   self.petitpotam),
            ("DFSCoerce",    self.dfscoerce),
            ("ShadowCoerce", self.shadowcoerce),
            ("MSEven",       self.mseven),
        ]
        return "  ".join(f"{name} {'✓' if ok else '✗'}" for name, ok in methods)


def _run_coerce_plus(host: str, env: TargetEnv) -> CoercePlusResult:
    """
    Run `nxc smb <host> --module coerce_plus` (detection mode — no LISTENER).
    Never passes LISTENER= — that would trigger actual coercion.

    Real nxc output format (confirmed against GOAD):
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, DFSCoerce
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, PetitPotam
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, PrinterBug
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, PrinterBug
        COERCE_PLUS 192.168.164.10  445  KINGSLANDING  VULNERABLE, MSEven

    Non-vulnerable methods produce NO output — absence means not vulnerable.
    PrinterBug may appear twice (two RPC endpoints); handled by set membership.
    """
    result = CoercePlusResult(host=host)

    cred_args = (
        ["-H", env.cred.nt_hash] if env.cred.nt_hash
        else ["-p", env.cred.password]
    )
    base_args = [
        host,
        "-u", env.cred.username,
        *cred_args,
        "-d", env.domain,
        "--module", "coerce_plus",
    ]

    rc, out, err = _run_nxc_smb(base_args, env, timeout=env.timeout + 20)

    if rc == -1:
        # rc == -1 is the sentinel for "subprocess did not complete": either the
        # nxc binary is missing, or it timed out / errored. Neither case means
        # "no coercion methods" — empty output here must NOT be read as a clean
        # host (that would understate attack viability). Flag and bail.
        if "nxc not found" in err:
            result.tool_unavailable = True
        else:
            result.errored = True
        return result

    result.raw_output = out + err

    # Only parse lines that start with the COERCE_PLUS tag — ignore SMB auth lines.
    # Format: "COERCE_PLUS <ip>  <port>  <hostname>  VULNERABLE, <MethodName>"
    # Non-vulnerable methods produce no output at all — absence = not vulnerable.
    # Method names are title-case in output; we compare lower-case.
    # PrinterBug may appear twice (two RPC endpoints) — set membership deduplicates.
    vulnerable_methods: set[str] = set()
    for line in (out + err).splitlines():
        if not line.lstrip().startswith("COERCE_PLUS"):
            continue
        if "vulnerable" not in line.lower():
            continue
        # Extract method name from the trailing field after the last comma.
        # e.g. "VULNERABLE, PrinterBug" → "printerbug"
        if "," in line:
            method_field = line.split(",")[-1].strip().lower()
            vulnerable_methods.add(method_field)

    result.printerbug   = "printerbug"   in vulnerable_methods
    result.petitpotam   = "petitpotam"   in vulnerable_methods
    result.dfscoerce    = "dfscoerce"    in vulnerable_methods
    result.shadowcoerce = "shadowcoerce" in vulnerable_methods
    result.mseven       = "mseven"       in vulnerable_methods

    return result


# ── CoercionAvailabilityCheck ────────────────────────────────────────────────

class CoercionAvailabilityCheck(BaseCheck):
    """
    Checks which SMB-based coercion methods are available across all in-scope
    targets using `nxc smb --module coerce_plus` (detection mode only —
    LISTENER is never set, so no authentication is actually triggered).

    Methods covered: PrinterBug (MS-RPRN), PetitPotam (MS-EFSRPC),
    DFSCoerce (MS-DFSNM), ShadowCoerce (MS-FSRVP), MSEven.

    Note: WebDAV/HTTP coercion paths (PetitPotam over WebDAV, mitm6) are NOT
    covered by coerce_plus — those are handled by the separate WebClient check.

    required=False: if no method is detected the attack may still be possible
    via out-of-band coercion; result is PARTIAL, not NOT VIABLE.
    """

    name = "SMB coercion methods available (coerce_plus)"
    required = False

    def _run(self) -> CheckResult:
        results: list[CoercePlusResult] = []
        for host in self.env.all_targets:
            results.append(_run_coerce_plus(host, self.env))

        if any(r.tool_unavailable for r in results):
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="nxc not found — install NetExec to enable coerce_plus checks.",
            )

        vulnerable    = [r for r in results if r.any_method]
        errored       = [r for r in results if r.errored]
        none_detected = [r for r in results
                         if not r.any_method and not r.errored and not r.tool_unavailable]

        def _hp(r):  # host (hostname) label
            return f"{self.env.hostname_map.get(r.host, r.host)} ({r.host})"

        if not vulnerable:
            # No methods found. If no host actually completed a probe, we can't
            # conclude anything — SKIP. Otherwise WARN, but call out any hosts
            # whose probe did not complete so they aren't read as "clean".
            if not none_detected:
                return CheckResult(
                    name=self.name, status=Status.SKIP,
                    detail=(
                        "coerce_plus could not complete on any target "
                        f"({', '.join(_hp(r) for r in errored) or 'none'}) — "
                        "coercion availability undetermined (timeout or error)."
                    ),
                )
            detail = (
                "coerce_plus found no vulnerable SMB coercion methods on "
                f"{', '.join(_hp(r) for r in none_detected)}. "
                "Out-of-band coercion (LLMNR/NBT-NS poisoning, mitm6, social engineering) "
                "may still be possible. WebDAV/HTTP paths checked separately."
            )
            if errored:
                detail += (f" NOTE: probe did not complete on {', '.join(_hp(r) for r in errored)} "
                           "(timeout/error) — those hosts are undetermined, not confirmed clean.")
            return CheckResult(name=self.name, status=Status.WARN, detail=detail)

        lines = []
        for r in vulnerable:
            hostname = self.env.hostname_map.get(r.host, r.host)
            lines.append(f"{hostname} ({r.host}): {r.method_summary()}")

        summary = "; ".join(lines)
        if none_detected:
            summary += f". No methods found on: {', '.join(_hp(r) for r in none_detected)}"
        if errored:
            summary += (f". Undetermined (timeout/error, not confirmed clean): "
                        f"{', '.join(_hp(r) for r in errored)}")

        return CheckResult(
            name=self.name, status=Status.PASS,
            detail=summary,
        )


# ── shared AD CS presence probe (authoritative) ─────────────────────────────

@dataclass
class AdcsVerdict:
    """Result of the authoritative AD CS-presence probe.

    status == PASS : >= 1 Enterprise CA registered in AD
    status == FAIL : no CA registered (container absent or empty)
    status == SKIP : LDAP bind/query inconclusive — caller should fall back to
                     tool-based detection. The shared cache is NOT written.
    """
    status: Status
    detail: str
    ca_names: list
    ca_hosts: list


def adcs_enrollment_verdict(env: TargetEnv) -> "AdcsVerdict":
    """
    Authoritative AD CS-presence probe shared by the adcs, esc11 and kerberos
    modules. Determines whether an Enterprise CA is registered in AD by
    searching for pKIEnrollmentService objects under the *forest-root*
    Configuration partition — the canonical CA registration object, and the
    same signal certipy/Certify key on.

    Why LDAP rather than tool-output parsing:
      - An empty result is a *definitive* "no CA" answer (gives a real FAIL,
        not a fragile SKIP), while a CA whose host VM is offline still has its
        object in AD, so it correctly stays PASS.
      - The Configuration NC is read from RootDSE rather than constructed from
        the domain name; in a child domain the Configuration partition lives at
        the forest root, so a constructed NC would false-FAIL.

    Caching: reads and writes env.shared_cache["adcs_deployed"] so the answer
    is computed once per run regardless of which module runs first. This is the
    ONLY place that key should be written — facts like "certsrv HTTP reachable"
    are separate and must not poison it.
    """
    cached = env.shared_cache.get("adcs_deployed")
    if cached is True:
        return AdcsVerdict(Status.PASS,
                           "AD CS deployed (confirmed earlier this run).", [], [])
    if cached is False:
        return AdcsVerdict(Status.FAIL,
                           "AD CS not deployed (confirmed earlier this run).", [], [])

    try:
        from ldap3 import Server, Connection, NTLM, SUBTREE, ALL
    except ImportError:
        return AdcsVerdict(Status.SKIP, "ldap3 not installed.", [], [])

    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        # ldap3 NTLM accepts the NT hash as "LMHASH:NTHASH"; use the empty-LM
        # prefix when only the NT hash is supplied.
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]
            auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
        else:
            auth_password = env.cred.password
        conn = Connection(server, user=env.cred.upn, password=auth_password,
                          authentication=NTLM, auto_bind=True)
    except Exception:
        return AdcsVerdict(Status.SKIP,
                           "LDAP bind refused/failed — inconclusive.", [], [])

    config_nc = None
    try:
        other = getattr(server.info, "other", {}) or {}
        vals = other.get("configurationNamingContext")
        if vals:
            config_nc = str(vals[0])
    except Exception:
        config_nc = None
    if not config_nc:
        try:
            conn.unbind()
        except Exception:
            pass
        return AdcsVerdict(Status.SKIP,
                           "Could not read RootDSE configurationNamingContext.", [], [])

    base = (f"CN=Enrollment Services,CN=Public Key Services,"
            f"CN=Services,{config_nc}")
    try:
        conn.search(search_base=base,
                    search_filter="(objectClass=pKIEnrollmentService)",
                    search_scope=SUBTREE, attributes=["cn", "dNSHostName"])
    except Exception:
        try:
            conn.unbind()
        except Exception:
            pass
        return AdcsVerdict(Status.SKIP, "LDAP search error — inconclusive.", [], [])

    result_code = (conn.result or {}).get("result")
    entries = list(conn.entries)

    if entries:
        ca_names, hosts = [], []
        for e in entries:
            ca_names.append(str(e["cn"]) if "cn" in e else "?")
            if "dNSHostName" in e and e["dNSHostName"]:
                hosts.append(str(e["dNSHostName"]))
        try:
            conn.unbind()
        except Exception:
            pass
        env.shared_cache["adcs_deployed"] = True
        detail = f"CA(s) registered in AD: {', '.join(ca_names)}"
        if hosts:
            detail += f" on {', '.join(hosts)}"
        detail += " (LDAP pKIEnrollmentService — authoritative)."
        return AdcsVerdict(Status.PASS, detail, ca_names, hosts)

    try:
        conn.unbind()
    except Exception:
        pass

    if result_code == 32:  # noSuchObject
        env.shared_cache["adcs_deployed"] = False
        return AdcsVerdict(Status.FAIL,
            "No Enrollment Services container in the Configuration partition — "
            "AD CS has never been deployed in this forest.", [], [])
    if result_code == 0:
        env.shared_cache["adcs_deployed"] = False
        return AdcsVerdict(Status.FAIL,
            "Enrollment Services container present but holds no "
            "pKIEnrollmentService objects — no Enterprise CA registered.", [], [])

    return AdcsVerdict(Status.SKIP,
                       f"Unexpected LDAP result code {result_code}.", [], [])
