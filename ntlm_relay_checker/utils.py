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
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from .checks.base import BaseCheck, CheckResult, Status
from .config import TargetEnv

try:
    from impacket.smbconnection import SMBConnection
    import impacket.ntlm as _impacket_ntlm
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


# ── internal helpers ────────────────────────────────────────────────────────

def _subprocess_run_with_retry(cmd: list[str], timeout: int,
                               retry_on_timeout: bool = False) -> tuple[int, str, str]:
    """Run cmd, returning (rc, stdout, stderr).

    Retries once on TimeoutExpired ONLY when retry_on_timeout=True (default: no
    retry). Every command this tool runs authenticates to the DC (nxc / crackmapexec
    / certipy), and a local TimeoutExpired does NOT prove the authentication never
    reached the DC — the subprocess may have already bound before we killed it. So an
    automatic retry can double-submit the same credential, adding an extra
    badPwdCount toward account lockout. For a read-only, no-side-effects tool that is
    the wrong trade: a timed-out auth is instead reported as a single inconclusive
    attempt (rc -1, "timeout"), which the callers surface as SKIP/UNKNOWN — the
    cardinal-rule-safe outcome. If transient timeouts cause spurious SKIPs, raise
    --timeout rather than silently re-authenticating.

    retry_on_timeout=True is opt-in for genuinely non-auth, idempotent local commands
    where a second attempt is free of authentication side effects.

    FileNotFoundError is intentionally NOT caught — if the tool is absent it will be
    absent on any retry too; the caller substitutes the fallback binary.
    """
    for attempt in range(2):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            if attempt == 0 and retry_on_timeout:
                continue   # one retry — only when the caller opted in
            return -1, "", "timeout"
    return -1, "", "timeout"  # unreachable, satisfies type checker


def _run_nxc_smb(args: list[str], env: TargetEnv, timeout: int = 30) -> tuple[int, str, str]:
    """Run `nxc smb <args>`, falling back to crackmapexec. Returns (rc, stdout, stderr)."""
    cmd = ["nxc", "smb"] + args
    try:
        return _subprocess_run_with_retry(cmd, timeout)
    except FileNotFoundError:
        cmd[0] = "crackmapexec"
        try:
            return _subprocess_run_with_retry(cmd, timeout)
        except FileNotFoundError:
            return -1, "", "nxc not found"


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

    if env.cred.nt_hash:
        nh = env.cred.nt_hash.split(":")[-1]
        auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
    else:
        auth_password = env.cred.password

    # Try plain LDAP first; fall back to LDAPS/TLS when signing is enforced
    # (posture 3a: signing=require/CB=never). The TLS channel supplies integrity
    # independently of LdapServerIntegrity, so the bind succeeds where 389 fails.
    import ssl as _ssl
    server = conn = None
    for _port, _ssl_flag in ((389, False), (636, True)):
        try:
            from ldap3 import Tls as _Tls
            _tls = _Tls(validate=_ssl.CERT_NONE) if _ssl_flag else None
            server = Server(env.dc_ip, port=_port, use_ssl=_ssl_flag, tls=_tls,
                            get_info=ALL, connect_timeout=env.timeout)
            conn = Connection(server, user=env.cred.upn, password=auth_password,
                              authentication=NTLM, auto_bind=True)
            break   # bound successfully
        except Exception:
            server = conn = None
    if conn is None:
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


# ── NTLMv1 auth-probe (shared check) ─────────────────────────────────────────

@dataclass
class NtlmV1ProbeResult:
    """Per-DC result of the NTLMv1 on-the-wire auth-probe."""
    dc: str
    ntlmv2_ok: bool = False          # control auth (NTLMv2) succeeded
    ntlmv1_accepted: bool = False    # forced-NTLMv1 auth also succeeded
    tool_unavailable: bool = False   # impacket not importable
    errored: bool = False            # NTLMv2 control failed → can't distinguish
    detail: str = ""

    @property
    def verdict(self) -> str:
        if self.tool_unavailable:
            return "tool-unavailable"
        if self.errored or not self.ntlmv2_ok:
            return "inconclusive"
        return "accepted" if self.ntlmv1_accepted else "refused"


def _smb_login(dc: str, env: TargetEnv, use_ntlmv2: bool) -> tuple[bool, str]:
    """
    Attempt a single SMB login against `dc` with the operator's own creds,
    forcing the NTLM version via impacket's module-level USE_NTLMv2 toggle.

    Returns (ok, error_string). Does not raise. The caller is responsible for
    saving/restoring the global toggle around the call.

    No writes, no service starts — a single AUTHENTICATE exchange, the same
    class of operation as the existing credentialed SMB auth checks.
    """
    _impacket_ntlm.USE_NTLMv2 = use_ntlmv2
    conn = None
    try:
        conn = SMBConnection(dc, dc, sess_port=445, timeout=env.timeout)
        lm = ""
        nt = ""
        password = env.cred.password or ""
        if env.cred.nt_hash:
            # impacket login() takes lmhash:nthash; supply empty LM half.
            nt = env.cred.nt_hash.split(":")[-1]
            lm = ""
            password = ""
        conn.login(
            env.cred.username, password,
            domain=env.cred.domain,
            lmhash=lm, nthash=nt,
        )
        return True, ""
    except Exception as exc:  # noqa: BLE001 — impacket raises many session-error types
        return False, str(exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def ntlmv1_auth_probe(dc: str, env: TargetEnv) -> NtlmV1ProbeResult:
    """
    Probe a single DC for NTLMv1 acceptance, non-destructively.

    Method (per the reworked plan):
      1. NTLMv2 control auth with the operator's valid creds. If it fails, we
         can't tell "NTLMv1 refused" from "creds/connectivity broken" → SKIP.
      2. Forced-NTLMv1 auth (impacket USE_NTLMv2=False) with the same creds.
         Success → NTLMv1 ACCEPTED (operational truth, incl. PDC forwarding).
         Failure after a passing control → refused on the tested path (level 5).

    The global impacket toggle is saved and restored around the forced attempt.
    ``_smb_login`` — the only in-process impacket-login site — is reached solely
    from here, and this probe is serialized process-wide by ntlmv1_probe_all()'s
    lock, so the toggle is only ever mutated inside a single-threaded critical
    section and NTLMv1 never leaks into any other (concurrent) auth. Do NOT call
    this directly from parallel code paths; go through ntlmv1_probe_all().
    """
    res = NtlmV1ProbeResult(dc=dc)
    if not IMPACKET_AVAILABLE:
        res.tool_unavailable = True
        res.detail = "impacket not installed."
        return res

    saved = _impacket_ntlm.USE_NTLMv2
    try:
        # 1) NTLMv2 control
        ok_v2, err_v2 = _smb_login(dc, env, use_ntlmv2=True)
        if not ok_v2:
            res.errored = True
            res.detail = f"NTLMv2 control auth failed ({err_v2[:120]}) — cannot test NTLMv1."
            return res
        res.ntlmv2_ok = True

        # 2) Forced NTLMv1
        ok_v1, err_v1 = _smb_login(dc, env, use_ntlmv2=False)
        res.ntlmv1_accepted = ok_v1
        res.detail = (
            "NTLMv1 AUTHENTICATE accepted." if ok_v1
            else f"NTLMv1 refused on the tested path ({err_v1[:80]})."
        )
        return res
    finally:
        _impacket_ntlm.USE_NTLMv2 = saved


# Serializes the NTLMv1 probe process-wide. ntlmv1_auth_probe flips the shared
# impacket USE_NTLMv2 global; two probes at once would corrupt each other's
# control/forced logins and the save/restore. The lock also makes the cache
# populate exactly once (double-checked below), so under --parallel the several
# OR-module threads that all miss the cache don't each re-run the per-DC probe
# (which would be duplicate logon events).
_NTLMV1_PROBE_LOCK = threading.Lock()


def ntlmv1_probe_all(env: TargetEnv) -> list["NtlmV1ProbeResult"]:
    """Per-DC NTLMv1 probe across env.dc_targets(), computed once per run and cached
    in shared_cache["ntlmv1_probe"]. Thread-safe (double-checked locking) — this is
    the only supported entry point for the probe; see _NTLMV1_PROBE_LOCK / the
    ntlmv1_auth_probe docstring for why serialization is required under --parallel.
    """
    cached = env.shared_cache.get("ntlmv1_probe")
    if cached is not None:                       # fast path: lock-free hit
        return cached
    with _NTLMV1_PROBE_LOCK:
        cached = env.shared_cache.get("ntlmv1_probe")   # re-check under the lock
        if cached is None:
            cached = [ntlmv1_auth_probe(dc, env) for dc in env.dc_targets()]
            env.shared_cache["ntlmv1_probe"] = cached
        return cached


class NtlmV1AuthProbeCheck(BaseCheck):
    """
    Detect whether NTLMv1 authentication is accepted, via a non-destructive
    on-the-wire auth-probe against each DC in dc_ips (valid creds, no coercion,
    no admin). This supersedes a static GPO/registry read because configured
    LmCompatibilityLevel does not equal effective behaviour — the PDC-emulator
    forwarding trap and the MS-NRPC ParameterControl bypass mean a level-5 DC
    can still sit in front of an NTLMv1-accepting validation path.

    Per DC: NTLMv2 control auth first, then a single forced-NTLMv1 attempt with
    the same creds. NTLMv1 accepted anywhere is the operationally relevant signal
    (it unlocks SMB→LDAP cross-protocol relay). The negative is reported as
    "refused on the tested path", never as a guarantee.

    required=False: this is a capability/context finding that widens relay paths;
    its absence does not block any attack, so it must never gate viability.
    Result is per-DC and surfaced for output.py to consume.
    """

    name = "NTLMv1 authentication accepted (SMB→LDAP relay enabler)"
    required = False

    def _run(self) -> CheckResult:
        if not IMPACKET_AVAILABLE:
            return CheckResult(
                name=self.name, status=Status.SKIP,
                detail="impacket not installed — cannot run NTLMv1 auth-probe. "
                       "Install with: pip install impacket",
            )

        # Idempotent + thread-safe: computed once per run and shared across every
        # module that hosts this check (double-checked lock in ntlmv1_probe_all —
        # avoids duplicate logon events and serializes the impacket toggle under
        # --parallel).
        results = ntlmv1_probe_all(self.env)

        def _label(r: NtlmV1ProbeResult) -> str:
            return f"{self.env.hostname_map.get(r.dc, r.dc)} ({r.dc})"

        accepted = [r for r in results if r.verdict == "accepted"]
        refused = [r for r in results if r.verdict == "refused"]
        inconclusive = [r for r in results if r.verdict == "inconclusive"]

        if accepted:
            detail = (
                f"NTLMv1 ACCEPTED via: {', '.join(_label(r) for r in accepted)}. "
                "Enables SMB→LDAP relay (no MIC → signing flags can be cleared), "
                "so LDAP-targeted chains (RBCD, Shadow Creds, LAPS, ADIDNS) become "
                "viable even where LDAP signing is enforced."
            )
            if refused:
                detail += f" Refused on the tested path: {', '.join(_label(r) for r in refused)}."
            if inconclusive:
                detail += (f" Inconclusive (NTLMv2 control failed): "
                           f"{', '.join(_label(r) for r in inconclusive)}.")
            return CheckResult(name=self.name, status=Status.PASS, detail=detail)

        if refused and not inconclusive:
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=(
                    f"NTLMv1 refused on the tested path for all probed DCs: "
                    f"{', '.join(_label(r) for r in refused)}. "
                    "Note: a refusal here is not a guarantee — the MS-NRPC "
                    "ParameterControl bypass means level-5 does not fully preclude "
                    "an NTLMv1 relay path elsewhere."
                ),
            )

        # Nothing accepted, and at least one DC was inconclusive (or all were).
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=(
                "Could not determine NTLMv1 acceptance — NTLMv2 control auth did not "
                f"succeed on: {', '.join(_label(r) for r in inconclusive) or 'any DC'}. "
                "Check credentials/connectivity."
                + (f" Refused on: {', '.join(_label(r) for r in refused)}." if refused else "")
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Centralised helper functions (consolidated 2026 — see "Centralise helpers"
# TODO item). These were previously duplicated verbatim across the check
# modules. Each module now imports from here instead of defining its own copy.
# ldap3 is imported lazily inside _ldap_connect so utils carries no module-level
# ldap3 dependency (matching adcs_enrollment_verdict above); the check classes
# keep their own module-level ldap3 imports for Server/NTLM/etc.
# ─────────────────────────────────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: int = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _run_nxc_ldap(args: list[str], env: TargetEnv, timeout: int = 20,
                  target: str | None = None) -> tuple[int, str, str]:
    auth = (["-H", env.cred.nt_hash] if env.cred.nt_hash
            else ["-p", env.cred.password])
    cmd = ["nxc", "ldap", target or env.dc_ip,
           "-u", env.cred.username,
           "-d", env.domain] + auth + args
    try:
        return _subprocess_run_with_retry(cmd, timeout)
    except FileNotFoundError:
        cmd[0] = "crackmapexec"
        try:
            return _subprocess_run_with_retry(cmd, timeout)
        except FileNotFoundError:
            return -1, "", "nxc not found"


def ldap_checker_output(env: TargetEnv) -> tuple[int, str, str]:
    """Run `nxc ldap --module ldap-checker` once per run and cache the result.

    The ldap-checker nxc module reports both LDAP signing and channel-binding
    posture in a single run. Eight check classes across six modules need that
    output (LdapSigningCheck / LdapChannelBindingCheck plus the LDAPS ACL-abuse
    and add-computer signing probes), so without caching the same command would
    be shelled out up to ten times per scan against the same DC.

    Caching: reads and writes env.shared_cache["ldap_checker"], so the command
    runs once regardless of which module reaches it first. Matches the lock-free,
    idempotent pattern of adcs_enrollment_verdict — under --parallel a race may
    run nxc twice (benign; last-write-wins on an identical value), and dict
    get/set is atomic under the GIL so there is no torn read. The cached value is
    the full (rc, out, err) tuple so every caller parses the same bytes.
    """
    cached = env.shared_cache.get("ldap_checker")
    if cached is not None:
        return cached
    result = _run_nxc_ldap(["--module", "ldap-checker"], env)
    env.shared_cache["ldap_checker"] = result
    return result


# ── per-DC signing / channel-binding fan-out ────────────────────────────────
# LDAP signing and channel binding are per-DC *effective* postures, exactly like
# NTLMv1 acceptance: a single child DC with signing off / CB not required is a
# viable LDAP-relay path (the attacker relays to the most permissive DC). These
# checks therefore fan out over env.dc_targets() and report the OPEN posture if it
# holds on ANY DC, mirroring NtlmV1AuthProbeCheck's "accepted anywhere" logic.
#
# The PRIMARY DC (env.dc_ip) is routed through the existing ldap_checker_output /
# _ldap_channel_binding_probe helpers so their caches — and the test monkeypatches
# that target them — are honored unchanged; additional DCs run fresh, targeted nxc
# / ldap3 probes. A single-DC environment therefore reduces to the previous
# primary-only behavior byte-for-byte. Full per-DC postures are cached so the five
# OR modules share one evaluation per DC (mirrors the ntlmv1_probe idempotency).

def _ldap_checker_for_dc(env: TargetEnv, dc: str) -> tuple[int, str, str]:
    """`nxc ldap --module ldap-checker` against a specific DC, cached per DC.

    The primary DC reuses ldap_checker_output(env) (shared with the LDAPS twins and
    honored by tests); other DCs cache under ``ldap_checker:<dc>``.
    """
    if dc == env.dc_ip:
        return ldap_checker_output(env)
    key = f"ldap_checker:{dc}"
    cached = env.shared_cache.get(key)
    if cached is not None:
        return cached
    result = _run_nxc_ldap(["--module", "ldap-checker"], env, target=dc)
    env.shared_cache[key] = result
    return result


def _signing_posture_for_dc(env: TargetEnv, dc: str) -> tuple[str, str]:
    """Return (token, detail) for one DC's LDAP signing posture.

    token ∈ {"open", "enforced", "unknown"}:
        open     — signing NOT enforced (relay to LDAP viable on this DC)
        enforced — signing REQUIRED (relay rejected on this DC)
        unknown  — could not determine (nxc unparseable + fallback inconclusive)

    Preserves the exact parse + anon-bind-fallback semantics of the previous
    single-DC LdapSigningCheck (anon-bind SUCCESS is inconclusive → "unknown",
    never "open" — a successful anonymous bind says nothing about signing).
    """
    rc, out, err = _ldap_checker_for_dc(env, dc)
    combined = (out + err).lower()
    if rc != -1:
        lines = combined.splitlines()
        # 1) Authoritative nxc ldap-checker verdict: the line names "ldap signing"
        #    AND states "…enforced". Anchoring on BOTH tokens means a stray line
        #    like "smb signing: true" or the nxc LDAP connection banner
        #    "(signing:none)" — neither of which contains "enforced" — cannot latch
        #    and mislabel LDAP signing. Scan ALL lines so a banner emitted before
        #    the verdict does not win by position (the old first-match-wins loop
        #    could pick a banner "(signing:…)" line and then fall through to SKIP).
        for line in lines:
            if "ldap signing" in line and "enforced" in line:
                if "not enforced" in line:
                    return "open", "nxc ldap-checker: LDAP signing NOT enforced"
                return "enforced", "nxc ldap-checker: LDAP signing REQUIRED"
        # 2) Older bare wording ("signing: true/false"), but skip SMB-signing and
        #    the LDAP connection banner, which carry their own "signing" tokens.
        for line in lines:
            if "smb" in line or "channel binding" in line or "(signing:" in line:
                continue
            if "signing: false" in line:
                return "open", "nxc ldap-checker: signing NOT enforced"
            if "signing: true" in line:
                return "enforced", "nxc ldap-checker: signing REQUIRED"
    # Fallback: anonymous LDAP bind. Success is INCONCLUSIVE for signing (→ unknown);
    # a signing-required rejection is the only negative signal we can trust.
    try:
        from ldap3 import ANONYMOUS, Connection, Server
    except ImportError:
        return "unknown", "nxc unparseable; ldap3 unavailable for fallback"
    try:
        server = Server(dc, connect_timeout=env.timeout)
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        if getattr(conn, "bound", False):
            try:
                conn.unbind()
            except Exception:
                pass
            return "unknown", "anon bind succeeded — inconclusive for signing"
    except Exception as exc:
        low = str(exc).lower()
        if "stronger" in low or "sign" in low:
            return "enforced", f"anon bind rejected (signing required): {exc}"
    return "unknown", "could not determine signing posture"


def _signing_postures(env: TargetEnv) -> dict[str, tuple[str, str]]:
    """{dc: (token, detail)} across env.dc_targets(), computed/cached once per run."""
    cached = env.shared_cache.get("ldap_signing_postures")
    if cached is None:
        cached = {dc: _signing_posture_for_dc(env, dc) for dc in env.dc_targets()}
        env.shared_cache["ldap_signing_postures"] = cached
    return cached


def _cb_probe_for_dc(env: TargetEnv, dc: str) -> Optional[bool]:
    """No-CBT LDAPS bind against a specific DC (see _ldap_channel_binding_probe).

    Primary reuses _ldap_channel_binding_probe(env) (cache + test monkeypatch
    honored); other DCs cache under ``ldap_cb_probe:<dc>``.
    """
    if dc == env.dc_ip:
        return _ldap_channel_binding_probe(env)
    key = f"ldap_cb_probe:{dc}"
    if key in env.shared_cache:
        return env.shared_cache[key]
    result = _ldap_channel_binding_probe_run(env, dc)
    env.shared_cache[key] = result
    return result


def _cb_posture_for_dc(env: TargetEnv, dc: str) -> tuple[str, str]:
    """Return (token, detail) for one DC's LDAP channel-binding posture.

    token ∈ {"never", "required", "when-supported", "unknown"}:
        never          — CB not required (TLS relay path open on this DC)
        required       — CB enforced ("Always") / no-CBT bind rejected (blocked)
        when-supported — CB "When Supported", or a no-CBT bind SUCCEEDED (cannot
                         distinguish Never from When-Supported) → surfaced as WARN
        unknown        — nxc unavailable, or probe inconclusive

    Mirrors the previous single-DC LdapChannelBindingCheck exactly (including that
    nxc-unavailable → unknown rather than probing, and probe-True → the ambiguous
    when-supported/WARN state, never a confident PASS).
    """
    rc, out, err = _ldap_checker_for_dc(env, dc)
    combined = (out + err).lower()
    if rc == -1:
        return "unknown", "nxc not available to check channel binding"
    if "channel binding is set to: never" in combined or "channel binding is not required" in combined:
        return "never", "nxc ldap-checker: channel binding Never"
    if "channel binding is set to: always" in combined or "channel binding is required" in combined:
        return "required", "nxc ldap-checker: channel binding Always/required"
    if "channel binding is set to: when supported" in combined:
        return "when-supported", "nxc ldap-checker: channel binding When Supported"
    # nxc output unparseable for CB → direct no-CBT LDAPS probe.
    probe = _cb_probe_for_dc(env, dc)
    if probe is True:
        return "when-supported", "no-CBT LDAPS bind succeeded (Never vs When-Supported ambiguous)"
    if probe is False:
        return "required", "no-CBT LDAPS bind rejected (SEC_E_BAD_BINDINGS)"
    return "unknown", "channel-binding probe inconclusive"


def _cb_postures(env: TargetEnv) -> dict[str, tuple[str, str]]:
    """{dc: (token, detail)} across env.dc_targets(), computed/cached once per run."""
    cached = env.shared_cache.get("ldap_cb_postures")
    if cached is None:
        cached = {dc: _cb_posture_for_dc(env, dc) for dc in env.dc_targets()}
        env.shared_cache["ldap_cb_postures"] = cached
    return cached


def _dc_list_label(env: TargetEnv, ips: list[str]) -> str:
    """'HOST (ip), ip2, …' using hostname_map where known — for detail strings."""
    parts = []
    for ip in ips:
        host = env.hostname_map.get(ip)
        parts.append(f"{host} ({ip})" if host else ip)
    return ", ".join(parts)


# ── LDAPS channel-binding fan-out for the Add-Computer / ACL-Abuse twins ─────
# These twins relay over ldaps:// specifically, so their CB interpretation differs
# from the shared LdapChannelBindingCheck: an *explicit* "When Supported" blocks the
# relayed no-CBT bind (FAIL, lab-confirmed), whereas a probe-only success is merely
# ambiguous (WARN — can't distinguish Never from When Supported). This helper reuses
# the same per-DC cached nxc / probe I/O but applies that twin mapping, and fans out
# over dc_targets() so a child DC with CB=Never is not missed (the #2 asymmetry, now
# closed for the twins too).

def _ldaps_cb_posture_for_dc(env: TargetEnv, dc: str) -> tuple[str, str]:
    """token ∈ {open, blocked, ambiguous, uncertain, unknown} for one DC:
        open      — CB Never (relay to this DC viable)
        blocked   — CB Always / When Supported / no-CBT bind rejected (relay blocked)
        ambiguous — no-CBT bind SUCCEEDED (Never vs When Supported indistinguishable)
        uncertain — nxc RAN but output unparseable and probe inconclusive
        unknown   — nxc timed out / missing and probe inconclusive (couldn't test)
    """
    rc, out, err = _ldap_checker_for_dc(env, dc)
    combined = (out + err).lower()
    if rc != -1:
        if "channel binding is set to: never" in combined or "channel binding is not required" in combined:
            return "open", "CB Never"
        if "channel binding is set to: always" in combined or "channel binding is required" in combined:
            return "blocked", "CB Always/required"
        if "channel binding is set to: when supported" in combined:
            return "blocked", "CB When Supported (relayed no-CBT bind fails, SEC_E_BAD_BINDINGS)"
    probe = _cb_probe_for_dc(env, dc)
    if probe is True:
        return "ambiguous", "no-CBT LDAPS bind succeeded (Never vs When Supported unknown)"
    if probe is False:
        return "blocked", "no-CBT LDAPS bind rejected (SEC_E_BAD_BINDINGS)"
    # probe inconclusive — distinguish a timed-out/absent nxc (couldn't test) from an
    # nxc that ran with unrecognised output (uncertain).
    if rc == -1:
        return "unknown", ("nxc ldap-checker timed out" if "timeout" in err.lower()
                           else "nxc not available")
    return "uncertain", "nxc output unparseable; direct LDAPS probe inconclusive"


def _ldaps_cb_postures(env: TargetEnv) -> dict[str, tuple[str, str]]:
    """{dc: (token, detail)} across env.dc_targets(), computed/cached once per run."""
    cached = env.shared_cache.get("ldaps_cb_postures")
    if cached is None:
        cached = {dc: _ldaps_cb_posture_for_dc(env, dc) for dc in env.dc_targets()}
        env.shared_cache["ldaps_cb_postures"] = cached
    return cached


def ldaps_cb_fanout(env: TargetEnv):
    """Aggregate the twins' LDAPS channel-binding posture across dc_targets().

    Returns (status, open_dcs, blocked_dcs, soft_dcs, unknown_dcs) where the lists are
    DC IPs and `soft_dcs` are the ambiguous/uncertain ones. Semantics mirror the shared
    signing/CB fan-out — the attacker relays to the most permissive DC:
        PASS  CB Never on ANY DC
        WARN  none Never, but some DC ambiguous/uncertain (can't confirm blocked)
        FAIL  blocked on ALL determinable DCs (none open/soft/unknown)
        SKIP  otherwise (a DC couldn't be tested and none is open/soft)
    Single-DC reduces to the previous per-twin result.
    """
    postures = _ldaps_cb_postures(env)
    open_dcs    = [dc for dc, (t, _) in postures.items() if t == "open"]
    blocked_dcs = [dc for dc, (t, _) in postures.items() if t == "blocked"]
    soft_dcs    = [dc for dc, (t, _) in postures.items() if t in ("ambiguous", "uncertain")]
    unknown_dcs = [dc for dc, (t, _) in postures.items() if t == "unknown"]
    if open_dcs:
        status = Status.PASS
    elif soft_dcs:
        status = Status.WARN
    elif blocked_dcs and not unknown_dcs:
        status = Status.FAIL
    else:
        status = Status.SKIP
    return status, open_dcs, blocked_dcs, soft_dcs, unknown_dcs


# ── shared LDAP relay-prerequisite check classes ────────────────────────────
# LdapSigningCheck and LdapChannelBindingCheck are prerequisites for every
# NTLM-relay-to-LDAP path (RBCD, Shadow Credentials, LAPS dump, ADIDNS). They
# were previously copy-pasted into each of those modules; defined once here and
# imported so the four copies cannot drift apart. The class *names* are load
# bearing — output.py's cross-protocol SMB→LDAP chain builder keys on the exact
# strings "LDAP signing not enforced" and "LDAP channel binding not required",
# so do not rename them.

class LdapSigningCheck(BaseCheck):
    """LDAP signing must not be enforced for relay to succeed.

    Primary signal is nxc's ldap-checker output (cached). If that is
    inconclusive, falls back to an unauthenticated ldap3 bind. A bind that
    fails with a "stronger auth required"/"sign" error proves signing IS
    enforced (FAIL). A *successful* anonymous bind, however, proves only that
    the host is up and permits anonymous binds — it says nothing about whether
    signing is enforced for authenticated (SASL/NTLM) binds, which is the bind
    a relay actually performs (LdapServerIntegrity governs those, not anonymous
    simple binds). So anon-bind success is inconclusive → SKIP, never PASS;
    treating it as PASS would feed a false VIABLE for RBCD/ShadowCreds/LAPS/ADIDNS.
    """

    name = "LDAP signing not enforced"
    # Optional: one of three *alternative* relay channels (signing / channel binding /
    # NTLMv1). The OR relay model (module_viability on RBCD/Shadow/LAPS/ADIDNS) decides
    # viability from the OR of these, so no single channel is individually required.
    required = False

    def _run(self) -> CheckResult:
        postures = _signing_postures(self.env)
        open_dcs     = [dc for dc, (tok, _) in postures.items() if tok == "open"]
        enforced_dcs = [dc for dc, (tok, _) in postures.items() if tok == "enforced"]
        unknown_dcs  = [dc for dc, (tok, _) in postures.items() if tok == "unknown"]
        multi = len(postures) > 1

        # PASS if signing is not enforced on ANY DC — the attacker relays to the
        # most permissive DC (mirrors NtlmV1AuthProbeCheck's "accepted anywhere").
        if open_dcs:
            note = ""
            if multi:
                blocked = enforced_dcs + unknown_dcs
                note = (f" (enforced/undetermined on {_dc_list_label(self.env, blocked)}, "
                        "but a relay to the permissive DC still succeeds)") if blocked else ""
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"LDAP signing NOT enforced on {_dc_list_label(self.env, open_dcs)} "
                       f"— relay to LDAP viable.{note}",
            )
        # FAIL only if signing is enforced on ALL probed DCs (none undeterminable).
        if enforced_dcs and not unknown_dcs:
            scope = "all probed DCs" if multi else _dc_list_label(self.env, enforced_dcs)
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"LDAP signing REQUIRED (LdapServerIntegrity=2) on {scope} — relay rejected.",
            )
        # Otherwise at least one DC is undeterminable and none is open → SKIP (a
        # permissive DC cannot be ruled out; must not read as viable OR as blocked).
        bits = []
        if enforced_dcs:
            bits.append(f"signing REQUIRED on {_dc_list_label(self.env, enforced_dcs)}")
        for dc in unknown_dcs:
            bits.append(f"{self.env.hostname_map.get(dc, dc)}: {postures[dc][1]}")
        detail = "Could not determine LDAP signing status"
        detail += (" — " + "; ".join(bits) + ".") if bits else "."
        return CheckResult(name=self.name, status=Status.SKIP, detail=detail)


class LdapChannelBindingCheck(BaseCheck):
    """LDAP channel binding must not be required for relay to succeed."""

    name = "LDAP channel binding not required"
    # Optional — alternative relay channel; the OR relay model supplies the verdict.
    required = False

    def _run(self) -> CheckResult:
        postures = _cb_postures(self.env)
        never_dcs    = [dc for dc, (tok, _) in postures.items() if tok == "never"]
        required_dcs = [dc for dc, (tok, _) in postures.items() if tok == "required"]
        whensup_dcs  = [dc for dc, (tok, _) in postures.items() if tok == "when-supported"]
        unknown_dcs  = [dc for dc, (tok, _) in postures.items() if tok == "unknown"]
        multi = len(postures) > 1

        # PASS if channel binding is Never on ANY DC — relay to LDAPS viable there.
        if never_dcs:
            note = ""
            if multi:
                other = required_dcs + whensup_dcs + unknown_dcs
                note = (f" (required/undetermined on {_dc_list_label(self.env, other)}, "
                        "but a relay to the permissive DC still succeeds)") if other else ""
            return CheckResult(
                name=self.name, status=Status.PASS,
                detail=f"LDAP channel binding NOT required (set to: Never) on "
                       f"{_dc_list_label(self.env, never_dcs)} — relay viable.{note}",
            )
        # No confirmed-Never DC, but some DC is 'When Supported' / probe-ambiguous → WARN.
        # Cannot distinguish Never from When Supported there (a relay fails under When
        # Supported with SEC_E_BAD_BINDINGS); the OR model correctly leaves the TLS path
        # closed unless an explicit PASS opens it.
        if whensup_dcs:
            return CheckResult(
                name=self.name, status=Status.WARN,
                detail=(
                    f"LDAP channel binding is 'When Supported' or unconfirmed on "
                    f"{_dc_list_label(self.env, whensup_dcs)} — ldaps:// relay path unconfirmed. "
                    "Verify LdapEnforceChannelBinding on the DC "
                    "(0=Never → viable, 1=When Supported → blocked, 2=Always → blocked)."
                ),
            )
        # FAIL only if channel binding is required on ALL probed DCs (none undeterminable).
        if required_dcs and not unknown_dcs:
            scope = "all probed DCs" if multi else _dc_list_label(self.env, required_dcs)
            return CheckResult(
                name=self.name, status=Status.FAIL,
                detail=f"LDAP channel binding REQUIRED on {scope} — relay blocked.",
            )
        # Undeterminable somewhere, nothing open/ambiguous → SKIP.
        return CheckResult(
            name=self.name, status=Status.SKIP,
            detail=("Channel binding status could not be determined — nxc output "
                    "unparseable and the direct LDAPS probe was inconclusive (636 may be "
                    "unreachable or have no DC certificate). If relaying to LDAPS, verify manually."),
        )


def _run_nxc_mssql(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    cmd = ["nxc", "mssql"] + args
    try:
        return _subprocess_run_with_retry(cmd, timeout)
    except FileNotFoundError:
        cmd[0] = "crackmapexec"
        try:
            return _subprocess_run_with_retry(cmd, timeout)
        except FileNotFoundError:
            return -1, "", "nxc not found"


# Resolved once per process: the certipy binary and the flag that forces a
# plaintext-LDAP connection. Cached to avoid re-running `certipy find -h`.
_CERTIPY_BIN: object = None          # str (binary name) | False (not installed) | None (unresolved)
_CERTIPY_SCHEME: Optional[list] = None  # e.g. ["-ldap-scheme", "ldap"] | [] (undetectable)


def _certipy_resolve() -> tuple[Optional[str], list]:
    """Resolve the certipy binary and the flag that forces plaintext LDAP.

    certipy defaults to LDAPS (636); a DC with no Enterprise CA has no
    auto-enrolled server-auth certificate, so LDAPS isn't available and
    `find` dies with an SSL/connection-reset error before reading anything.
    Forcing plain LDAP fixes it. The flag is version-dependent — v5 uses
    ``-ldap-scheme ldap``, v4 uses ``-scheme ldap`` — so it's feature-detected
    from ``certipy find -h`` rather than parsed from a version string (survives
    future flag renames). Result is cached for the process.
    """
    global _CERTIPY_BIN, _CERTIPY_SCHEME
    if _CERTIPY_BIN is None:
        _CERTIPY_BIN = next((b for b in ("certipy-ad", "certipy")
                             if shutil.which(b)), False)
        scheme: list = []
        if _CERTIPY_BIN:
            help_text = ""
            try:
                r = subprocess.run([_CERTIPY_BIN, "find", "-h"],
                                   capture_output=True, text=True, timeout=15)
                help_text = (r.stdout or "") + (r.stderr or "")
            except Exception:  # noqa: BLE001 — detection is best-effort
                help_text = ""
            if "-ldap-scheme" in help_text:
                scheme = ["-ldap-scheme", "ldap"]
            elif "-scheme" in help_text:
                scheme = ["-scheme", "ldap"]
        _CERTIPY_SCHEME = scheme
    return (_CERTIPY_BIN or None), (_CERTIPY_SCHEME or [])


def _run_certipy(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run certipy-ad (fallback: certipy) for enumeration-only commands.

    For ``find`` (the only subcommand RelayHound uses), plaintext LDAP is forced
    so enrichment doesn't transport-fail against DCs with no LDAPS certificate
    (e.g. ADCS-free DCs, which return Errno 104 / SSL-wrap reset on 636).
    Callers needing a longer window (e.g. esc11's full scans) pass timeout
    explicitly.
    """
    global _CERTIPY_BIN, _CERTIPY_SCHEME
    binary, scheme = _certipy_resolve()
    if binary is None:
        return -1, "", "certipy-ad/certipy not found"
    cmd = list(args)
    if "find" in cmd and scheme and not any(
            a in ("-ldap-scheme", "-scheme") for a in cmd):
        cmd = cmd + scheme
    try:
        return _subprocess_run_with_retry([binary] + cmd, timeout)
    except FileNotFoundError:
        # Binary vanished between resolve and run (unlikely). Reset the cache to
        # None so the next call re-runs _certipy_resolve (its gate is
        # `_CERTIPY_BIN is None`) — re-resolution will record it as absent (False)
        # if it's truly gone, or recover it if the disappearance was transient.
        _CERTIPY_BIN = None
        _CERTIPY_SCHEME = None
        return -1, "", "certipy-ad/certipy not found"


def _certipy_ca_present(text: str) -> bool:
    """True iff certipy `find` output indicates at least one Enterprise CA.

    Robust against the zero case: certipy prints ``Found 0 certificate
    authorities`` / ``Could not find any CAs`` on an ADCS-free domain, and both
    contain the substring ``certificate authorit`` — so the naive
    ``"certificate authorit" in output`` test false-PASSes. The per-CA detail
    block prints ``CA Name``, which is absent when no CA exists; that's the
    reliable positive signal, alongside an explicit ``Found N…`` count (N>=1).
    """
    low = text.lower()
    if "could not find any ca" in low or re.search(
            r"found\s+0\s+certificate\s+authorit", low):
        return False
    if "ca name" in low:
        return True
    m = re.search(r"found\s+(\d+)\s+certificate\s+authorit", low)
    return bool(m and int(m.group(1)) > 0)


def _certipy_enumerated(text: str) -> bool:
    """True if certipy actually enumerated the directory's CA/template data.

    certipy (run with -ldap-scheme ldap) exits cleanly even when the DC is
    unreachable, printing only a connection error — which must NOT be read as
    'no CA exists'. A genuine enumeration names the CA/template/enrollment
    sections (even when it found zero, e.g. "Found 0 certificate authorities"
    or "Could not find any CAs"); their absence means certipy never got the
    data, so callers should treat that as un-testable (defer to an LDAP probe /
    SKIP), not as a definitive negative.
    """
    low = text.lower()
    # Match certipy's *result* forms only: a "Found N certificate
    # authorities/templates" count line (N may be 0 — a genuine zero-result
    # enumeration), the explicit no-CA message ("Could not find any CAs"), or a
    # per-CA "CA Name :" detail block. Do NOT match a bare "certificate
    # authorit"/"certificate template"/"enrollment service" noun phrase: those
    # also occur in certipy *progress* lines ("Finding certificate templates")
    # and *error* sentences ("failed to enumerate certificate templates:
    # connection refused" / "Could not connect to enrollment service: timed
    # out"), which are NOT evidence the directory was actually read. Reading an
    # error as "enumerated" flips a caller's defer/SKIP into a confident
    # negative — e.g. a false FAIL on the Shadow-Credentials "DC has KDC
    # certificate" required gate → whole module NOT VIABLE. Erring toward False
    # is safe: every caller treats False as the conservative branch (defer to an
    # LDAP probe / SKIP), never a false VIABLE.
    if re.search(r"found\s+\d+\s+(?:enabled\s+)?certificate\s+(?:authorit|template)", low):
        return True
    if "could not find any ca" in low:
        return True
    if "ca name" in low:
        return True
    return False


def _run_bloodyad(args: list[str], env: TargetEnv, timeout: int = 20) -> tuple[int, str, str]:
    """Run bloodyAD with enumeration-only args.

    Pass-the-hash uses bloodyAD's documented `-p :NTHASH` form (colon-prefixed,
    stable across bloodyAD versions). Note bloodyAD has NO hash flag — `-H` is
    `--host` — so the old `-H <hash>` spelling in one module was broken under
    -H/PTH. `--host <dc_ip>` (an IP) is sufficient; the version-fragile
    `--dc-ip` arg is intentionally not added.
    """
    if env.cred.nt_hash:
        nh = env.cred.nt_hash.split(":")[-1]   # strip LM: prefix if present
        auth = ["-p", f":{nh}"]
    else:
        auth = ["-p", env.cred.password]
    cmd = ["bloodyAD", "--host", env.dc_ip,
           "-d", env.domain,
           "-u", env.cred.username] + auth + args
    try:
        return _subprocess_run_with_retry(cmd, timeout)
    except FileNotFoundError:
        return -1, "", "bloodyAD not found"


def _ldap_connect(env: TargetEnv) -> Optional[object]:
    """PTH-aware NTLM bind to the DC's LDAP service.

    Canonical version: handles pass-the-hash by passing the NT hash as
    "LMHASH:NTHASH" in the ldap3 password field (empty-LM prefix). Four modules
    previously shipped a non-PTH copy that passed env.cred.password (None under
    -H), silently breaking their LDAP checks with a hash — this fixes that.
    ldap3 is imported lazily so utils has no module-level ldap3 dependency.
    """
    try:
        from ldap3 import Server, Connection, ALL, NTLM
    except ImportError:
        return None
    try:
        server = Server(env.dc_ip, get_info=ALL, connect_timeout=env.timeout)
        # ldap3 NTLM accepts the NT hash as "LMHASH:NTHASH" in the password
        # field. Use the empty LM hash prefix when only the NT hash is supplied.
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]   # strip LM: prefix if present
            auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
        else:
            auth_password = env.cred.password
        conn = Connection(server, user=env.cred.upn, password=auth_password,
                          authentication=NTLM, auto_bind=True)
        return conn
    except Exception:
        return None


def _ldap_channel_binding_probe(env: TargetEnv) -> Optional[bool]:
    """Fallback determination of LDAPS channel-binding (EPA) posture via a direct
    ldap3 NTLM bind over LDAPS. Used only when nxc's ldap-checker output is
    unparseable (the last-resort WARN path of the channel-binding checks).

    Mechanism: ldap3 sends NO channel-binding token unless the opt-in
    ``channel_binding`` parameter is set, so a default NTLM bind over LDAPS (636)
    is exactly a "no-CBT" bind. A DC that requires channel binding ("Always")
    rejects it with SEC_E_BAD_BINDINGS (LDAP error ``data 80090346``); a DC that
    does not require it accepts the bind. Read-only — an auth attempt performs
    no writes (same class of operation as _ldap_connect over 389, and as the
    LDAPS binds nxc's ldap-checker already performs on our behalf).

    Returns:
        True  — bind succeeded -> channel binding NOT required -> relay viable.
        False — bind rejected with 80090346 -> channel binding REQUIRED -> blocked.
        None  — indeterminate (ldap3 absent, 636 unreachable, TLS handshake
                failure, generic auth failure, or any other error) -> the caller
                keeps its WARN. A false PASS is therefore impossible: PASS only on
                a genuine successful no-CBT bind, FAIL only on the specific
                bad-bindings error, everything else stays WARN.

    Cached in ``env.shared_cache["ldap_cb_probe"]`` (membership-keyed so a None
    result is cached too) so the bind runs at most once per scan even though
    several modules include a channel-binding check — mirrors the idempotent
    caching of ldap_checker_output.
    """
    if "ldap_cb_probe" in env.shared_cache:
        return env.shared_cache["ldap_cb_probe"]
    result = _ldap_channel_binding_probe_run(env)
    env.shared_cache["ldap_cb_probe"] = result
    return result


def _ldap_channel_binding_probe_run(env: TargetEnv, dc: str | None = None) -> Optional[bool]:
    """Uncached worker for _ldap_channel_binding_probe (see its docstring).

    Binds ``dc`` when given (per-DC fan-out), else the primary env.dc_ip.
    """
    try:
        import ssl

        from ldap3 import NTLM, Connection, Server, Tls
    except ImportError:
        return None

    # ldap3 NTLM accepts the NT hash as "LMHASH:NTHASH"; use the empty-LM prefix
    # when only the NT hash is supplied (mirrors _ldap_connect).
    if env.cred.nt_hash:
        nh = env.cred.nt_hash.split(":")[-1]
        auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
    else:
        auth_password = env.cred.password

    conn = None
    try:
        tls = Tls(validate=ssl.CERT_NONE)   # DC LDAPS certs are typically self-signed
        server = Server(dc or env.dc_ip, port=636, use_ssl=True, tls=tls,
                        connect_timeout=env.timeout)
        # Crucially we do NOT pass channel_binding=, so no CBT is sent — this is
        # the "no-CBT LDAPS bind" the determination depends on.
        conn = Connection(server, user=env.cred.upn, password=auth_password,
                          authentication=NTLM, receive_timeout=env.timeout)
        if conn.bind():
            return True   # no-CBT bind accepted -> channel binding not required
        # Bind failed: inspect the result for the bad-bindings signal.
        msg = ""
        try:
            if conn.result:
                msg = f"{conn.result.get('message', '')} {conn.result.get('description', '')}"
        except Exception:
            msg = ""
        msg = f"{msg} {getattr(conn, 'last_error', '') or ''}".lower()
        if "80090346" in msg:
            return False  # SEC_E_BAD_BINDINGS -> channel binding required
        return None       # some other auth failure -> cannot determine CB
    except Exception as exc:
        # TLS handshake failure / 636 unreachable / ldap3 internal error. The
        # bad-bindings error can also surface as an exception on some paths.
        if "80090346" in str(exc).lower():
            return False
        return None
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def _ldap_connect_tls(env: "TargetEnv") -> Optional[object]:
    """PTH-aware NTLM bind to the DC's LDAPS service (port 636, TLS, no CBT).

    Used as a fallback when plain _ldap_connect (port 389) fails because LDAP
    signing is enforced — the TLS channel carries integrity so the DC accepts the
    bind regardless of the LdapServerIntegrity policy. This is exactly the channel
    the relay uses at posture 3a (signing=require / CB=never), so if the relay is
    viable here, the tool's own enumeration must be too.

    Caching: keyed on ``env.shared_cache["ldap_conn_tls_ok"]`` (True/None).
    Unlike _ldap_connect we cache *reachability* only (not the connection object,
    which is stateful) — callers get a fresh connection each time so they can
    search and unbind independently.

    Returns the bound ldap3 Connection on success, None on any failure.
    """
    try:
        import ssl
        from ldap3 import Server, Connection, ALL, NTLM, Tls
    except ImportError:
        return None
    try:
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(env.dc_ip, port=636, use_ssl=True, tls=tls,
                        get_info=ALL, connect_timeout=env.timeout)
        if env.cred.nt_hash:
            nh = env.cred.nt_hash.split(":")[-1]
            auth_password = f"aad3b435b51404eeaad3b435b51404ee:{nh}"
        else:
            auth_password = env.cred.password
        conn = Connection(server, user=env.cred.upn, password=auth_password,
                          authentication=NTLM, auto_bind=True)
        return conn
    except Exception:
        return None


def _ldap_connect_with_tls_fallback(env: "TargetEnv") -> "tuple[Optional[object], bool]":
    """Try plain LDAP first; fall back to LDAPS/TLS when signing is enforced.

    Returns (conn, via_tls):
        conn    — bound ldap3 Connection, or None if both paths failed.
        via_tls — True if the TLS fallback was used (plain bind failed).

    Plain LDAP fails silently (returns None) when the DC enforces signing
    (LdapServerIntegrity=2, posture 3a). The TLS path succeeds at 3a because
    the TLS channel supplies integrity independently of the signing policy.
    Callers that only care whether they have a connection can ignore via_tls;
    those that want to note the transport (for detail strings) can use it.
    """
    conn = _ldap_connect(env)
    if conn is not None:
        return conn, False
    conn = _ldap_connect_tls(env)
    return conn, True


def _dns_srv_ips(domain: str, dns_server: str, timeout: int = 3) -> set[str]:
    """
    Query _ldap._tcp.dc._msdcs.<domain> SRV records against dns_server.
    Returns the set of IPs the SRV target hostnames resolve to.

    Uses raw DNS UDP sockets — no dnspython or other external library needed.
    Queries the AD-integrated DNS server (dc_ip) so internal zones resolve.
    """
    srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        tid = os.urandom(2)
        header = tid + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        parts = srv_name.encode('ascii').split(b'.')
        qname = b''.join(bytes([len(p)]) + p for p in parts) + b'\x00'
        question = qname + b'\x00\x21\x00\x01'   # QTYPE=SRV(33), QCLASS=IN(1)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + question, (dns_server, 53))
        resp, _ = s.recvfrom(4096)
        s.close()
    except OSError:
        return set()

    # A well-formed DNS reply is at least a 12-byte header; anything shorter is
    # truncated/garbage. Guard before unpacking (and before the pos=12 question
    # walk below) so a malformed UDP reply returns an empty set instead of
    # raising struct.error/IndexError out of the function — callers like
    # smb.py:_is_dc invoke this without their own try/except.
    if len(resp) < 12:
        return set()
    ancount = struct.unpack('!H', resp[6:8])[0]
    if ancount == 0:
        return set()

    def _decode_name(buf: bytes, offset: int) -> tuple[str, int]:
        labels: list[str] = []
        visited: set[int] = set()
        jumped = False
        end_offset = offset
        while offset < len(buf):
            if offset in visited:
                break
            visited.add(offset)
            length = buf[offset]
            if length & 0xc0 == 0xc0:
                if offset + 1 >= len(buf):
                    break
                ptr = struct.unpack('!H', buf[offset:offset+2])[0] & 0x3fff
                if not jumped:
                    end_offset = offset + 2
                jumped = True
                offset = ptr
            elif length == 0:
                if not jumped:
                    end_offset = offset + 1
                break
            else:
                labels.append(buf[offset+1:offset+1+length].decode('ascii', 'replace'))
                offset += length + 1
                if not jumped:
                    end_offset = offset
        return '.'.join(labels).lower(), end_offset

    # Skip question section
    pos = 12
    while pos < len(resp):
        if resp[pos] & 0xc0 == 0xc0:
            pos += 2
            break
        if resp[pos] == 0:
            pos += 1
            break
        pos += resp[pos] + 1
    pos += 4  # QTYPE + QCLASS

    hostnames: list[str] = []
    for _ in range(ancount):
        if pos >= len(resp):
            break
        _, pos = _decode_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype  = struct.unpack('!H', resp[pos:pos+2])[0]
        rdlen  = struct.unpack('!H', resp[pos+8:pos+10])[0]
        pos += 10
        if rtype == 33 and rdlen > 6:   # SRV
            target_name, _ = _decode_name(resp, pos + 6)
            if target_name:
                hostnames.append(target_name)
        pos += rdlen

    # Resolve each SRV target hostname → IP via A query to same DNS server
    ips: set[str] = set()
    for hostname in hostnames:
        try:
            tid2 = os.urandom(2)
            header2 = tid2 + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            parts2 = hostname.rstrip('.').encode('ascii').split(b'.')
            qname2 = b''.join(bytes([len(p)]) + p for p in parts2) + b'\x00'
            question2 = qname2 + b'\x00\x01\x00\x01'   # QTYPE=A(1), QCLASS=IN(1)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.settimeout(timeout)
            s2.sendto(header2 + question2, (dns_server, 53))
            resp2, _ = s2.recvfrom(4096)
            s2.close()
            ancount2 = struct.unpack('!H', resp2[6:8])[0]
            pos2 = 12
            while pos2 < len(resp2):
                if resp2[pos2] & 0xc0 == 0xc0:
                    pos2 += 2; break
                if resp2[pos2] == 0:
                    pos2 += 1; break
                pos2 += resp2[pos2] + 1
            pos2 += 4
            for _ in range(ancount2):
                if pos2 >= len(resp2): break
                _, pos2 = _decode_name(resp2, pos2)
                if pos2 + 10 > len(resp2): break
                rtype2  = struct.unpack('!H', resp2[pos2:pos2+2])[0]
                rdlen2  = struct.unpack('!H', resp2[pos2+8:pos2+10])[0]
                pos2 += 10
                if rtype2 == 1 and rdlen2 == 4:   # A record
                    ips.add('.'.join(str(b) for b in resp2[pos2:pos2+4]))
                pos2 += rdlen2
        except (OSError, struct.error, IndexError):
            try:
                ip = socket.gethostbyname(hostname.rstrip('.'))
                ips.add(ip)
            except OSError:
                pass

    return ips