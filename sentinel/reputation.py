from __future__ import annotations

from dataclasses import dataclass, asdict, field
from pathlib import Path
import json
import os
import subprocess

from .database import Database

SIGNED_EXTENSIONS={".exe",".dll",".msi",".sys",".ocx",".cpl"}
SENSITIVE_LOCATIONS=("\\downloads\\","\\temp\\","\\appdata\\local\\temp\\","/downloads/","/temp/","/appdata/local/temp/")


@dataclass(slots=True)
class AuthenticodeDetails:
    status: str = ""
    publisher: str = ""
    issuer: str = ""
    thumbprint: str = ""
    valid_from: str = ""
    valid_to: str = ""
    timestamp_signer: str = ""
    status_message: str = ""

    def to_dict(self):
        return asdict(self)


def _native_windows_system_directory() -> Path:
    """Resolve the native Windows system directory without trusting PATH/SystemRoot."""
    if os.name != "nt":
        raise OSError("native Windows system directory is unavailable")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = int(get_system_directory(buffer, size))
    if length <= 0 or length >= size:
        raise OSError(f"GetSystemDirectoryW failed: {ctypes.get_last_error()}")
    return Path(buffer.value)


def _authenticode_command(path: Path) -> tuple[list[str], dict[str, str]]:
    """Build a parser-safe Authenticode command.

    The filename and OS module path are encoded as data. User-controlled path
    text is never concatenated into PowerShell syntax. The child emits a
    minimal Base64 field protocol rather than relying on Utility/ConvertTo-Json,
    which reduces module-loading variance on Windows PowerShell 5.1.
    """
    import base64

    system_dir = _native_windows_system_directory()
    ps_root = system_dir / "WindowsPowerShell" / "v1.0"
    powershell = ps_root / "powershell.exe"
    security_module = ps_root / "Modules" / "Microsoft.PowerShell.Security" / "Microsoft.PowerShell.Security.psd1"
    for required in (powershell, security_module):
        if not required.is_file():
            raise OSError(f"required native PowerShell component missing: {required}")

    def b64(value: str) -> str:
        return base64.b64encode(value.encode("utf-8", "strict")).decode("ascii")

    # Fixed script shape. Only Base64 data literals vary; Base64 cannot break
    # out of the single-quoted PowerShell literals below.
    script = (
        "$ErrorActionPreference='Stop';"
        "$PSModuleAutoLoadingPreference='None';"
        "$u=[System.Text.Encoding]::UTF8;"
        f"$p=$u.GetString([Convert]::FromBase64String('{b64(str(path))}'));"
        f"$sm=$u.GetString([Convert]::FromBase64String('{b64(str(security_module))}'));"
        "Import-Module -LiteralPath $sm -Force -ErrorAction Stop;"
        "$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;"
        "$c=$s.SignerCertificate;$t=$s.TimeStamperCertificate;"
        "$pub=if($c){[string]$c.Subject}else{''};"
        "$iss=if($c){[string]$c.Issuer}else{''};"
        "$th=if($c){[string]$c.Thumbprint}else{''};"
        "$vf=if($c){$c.NotBefore.ToUniversalTime().ToString('o')}else{''};"
        "$vt=if($c){$c.NotAfter.ToUniversalTime().ToString('o')}else{''};"
        "$ts=if($t){[string]$t.Subject}else{''};"
        "function _b([object]$v){if($null -eq $v){$x=''}else{$x=[string]$v};"
        "[Convert]::ToBase64String($u.GetBytes($x))};"
        "$parts=@((_b ([string]$s.Status)),(_b ([string]$s.StatusMessage)),"
        "(_b $pub),(_b $iss),(_b $th),(_b $vf),(_b $vt),(_b $ts));"
        "[Console]::Out.WriteLine('BCS-AUTH1|'+($parts -join '|'))"
    )
    encoded_script = base64.b64encode(script.encode("utf-16le", "strict")).decode("ascii")

    windows_dir = system_dir.parent
    env = os.environ.copy()
    env["SystemRoot"] = str(windows_dir)
    env["WINDIR"] = str(windows_dir)
    # Keep lookup constrained to the native OS module tree. Security is still
    # imported by exact literal path; this variable is defensive for nested OS dependencies.
    env["PSModulePath"] = str(ps_root / "Modules")
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded_script,
    ]
    return command, env


def _decode_authenticode_protocol(stdout: str) -> dict[str, str]:
    """Decode the fixed BCS-AUTH1 protocol emitted by native PowerShell."""
    import base64

    line = ""
    for candidate in reversed(str(stdout or "").splitlines()):
        if candidate.startswith("BCS-AUTH1|"):
            line = candidate
            break
    if not line:
        raise ValueError("Authenticode protocol marker missing")
    parts = line.split("|")
    if len(parts) != 9 or parts[0] != "BCS-AUTH1":
        raise ValueError("Authenticode protocol field count invalid")
    names = (
        "Status", "StatusMessage", "Publisher", "Issuer", "Thumbprint",
        "ValidFrom", "ValidTo", "TimestampSigner",
    )
    decoded: dict[str, str] = {}
    for name, raw in zip(names, parts[1:]):
        try:
            decoded[name] = base64.b64decode(raw, validate=True).decode("utf-8", "strict")
        except Exception as exc:
            raise ValueError(f"Authenticode protocol field {name} invalid") from exc
    return decoded


def _map_winverifytrust_result(code: int) -> tuple[str, str]:
    """Map WinVerifyTrust LONG results to BC Sentinel's bounded status model."""
    value = int(code) & 0xFFFFFFFF
    if value == 0:
        return "Valid", ""
    # Microsoft documents these as the common no-signature / unsupported-subject
    # outcomes for the generic trust provider. Treat them as NotSigned rather
    # than as a successful signature verdict.
    not_signed = {
        0x800B0100,  # TRUST_E_NOSIGNATURE
        0x800B0001,  # TRUST_E_PROVIDER_UNKNOWN
        0x800B0003,  # TRUST_E_SUBJECT_FORM_UNKNOWN
    }
    if value in not_signed:
        return "NotSigned", f"WinVerifyTrust: 0x{value:08X}"
    return "UnknownError", f"WinVerifyTrust failed: 0x{value:08X}"


def _winverifytrust_status(path: Path) -> tuple[str, str]:
    """Verify file trust with the native Windows WinVerifyTrust API.

    This is the authoritative local validity gate. It does not invoke a shell,
    does not consult PATH, and uses cache-only URL retrieval so the check does
    not initiate network revocation lookups.
    """
    if os.name != "nt":
        return "Unsupported", ""

    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", wintypes.LPVOID),
            ("pSIPClientData", wintypes.LPVOID),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", wintypes.LPVOID),
        ]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    target = str(Path(path).absolute())
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = target
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.pPolicyCallbackData = None
    data.pSIPClientData = None
    data.dwUIChoice = 2                 # WTD_UI_NONE
    data.fdwRevocationChecks = 0        # WTD_REVOKE_NONE
    data.dwUnionChoice = 1              # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 0              # WTD_STATEACTION_IGNORE
    data.hWVTStateData = None
    data.pwszURLReference = None
    # No revocation network access; only locally cached information may be used.
    data.dwProvFlags = 0x10 | 0x1000    # WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    data.dwUIContext = 0                # WTD_UICONTEXT_EXECUTE
    data.pSignatureSettings = None

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    verify = wintrust.WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), wintypes.LPVOID]
    verify.restype = ctypes.c_long
    result = int(verify(None, ctypes.byref(action), ctypes.byref(data)))
    return _map_winverifytrust_result(result)


def _inspect_authenticode_powershell_metadata(path: Path) -> AuthenticodeDetails:
    """Best-effort certificate metadata via hardened native Windows PowerShell.

    Trust validity is *not* decided here; WinVerifyTrust is authoritative.
    """
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        command, child_env = _authenticode_command(Path(path))
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=6.0,
            creationflags=flags,
            env=child_env,
            check=False,
        )
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0 or not stdout:
            detail = stderr or stdout or f"PowerShell exited with code {proc.returncode}"
            return AuthenticodeDetails(status="UnknownError", status_message=detail[:500])
        try:
            payload = _decode_authenticode_protocol(stdout)
        except Exception as exc:
            detail = stderr or stdout
            return AuthenticodeDetails(
                status="UnknownError",
                status_message=f"Invalid Authenticode protocol: {type(exc).__name__}: {exc}; {detail}"[:500],
            )
        return AuthenticodeDetails(
            status=str(payload.get("Status") or "UnknownError"),
            publisher=str(payload.get("Publisher") or ""),
            issuer=str(payload.get("Issuer") or ""),
            thumbprint=str(payload.get("Thumbprint") or ""),
            valid_from=str(payload.get("ValidFrom") or ""),
            valid_to=str(payload.get("ValidTo") or ""),
            timestamp_signer=str(payload.get("TimestampSigner") or ""),
            status_message=str(payload.get("StatusMessage") or ""),
        )
    except Exception as exc:
        return AuthenticodeDetails(status="UnknownError", status_message=f"{type(exc).__name__}: {exc}"[:500])


def inspect_authenticode_details(path: Path) -> AuthenticodeDetails:
    """Fail-closed local Authenticode/certificate context without cloud access.

    Native WinVerifyTrust is authoritative for the trust status. Hardened
    PowerShell is used only to enrich a natively valid signature with human-
    readable certificate metadata. Metadata failure cannot downgrade a native
    Valid verdict, and a native non-valid verdict is never upgraded by metadata.
    """
    if os.name != "nt":
        return AuthenticodeDetails(status="Unsupported")

    try:
        native_status, native_message = _winverifytrust_status(Path(path))
    except Exception as exc:
        return AuthenticodeDetails(
            status="UnknownError",
            status_message=f"WinVerifyTrust exception: {type(exc).__name__}: {exc}"[:500],
        )

    if native_status != "Valid":
        return AuthenticodeDetails(status=native_status, status_message=native_message[:500])

    metadata = _inspect_authenticode_powershell_metadata(Path(path))
    if metadata.status == "Valid":
        return metadata

    # Native trust remains authoritative. Missing metadata is conservative: no
    # publisher allowlist match is possible when publisher is blank.
    detail = metadata.status_message or metadata.status or "metadata unavailable"
    return AuthenticodeDetails(
        status="Valid",
        status_message=f"WinVerifyTrust=Valid; certificate metadata unavailable: {detail}"[:500],
    )


def inspect_authenticode(path: Path) -> tuple[str, str]:
    """Compatibility wrapper retained for v0.3.x callers/tests."""
    details = inspect_authenticode_details(path)
    return details.status, details.publisher


@dataclass(slots=True)
class ReputationResult:
    signature_status: str = ""
    publisher: str = ""
    local_trust: str = "unknown"
    score_delta: int = 0
    reasons: list[str] = field(default_factory=list)
    cached: bool = False
    issuer: str = ""
    thumbprint: str = ""
    valid_from: str = ""
    valid_to: str = ""
    timestamp_signer: str = ""
    status_message: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observations: int = 0
    path_count: int = 0
    prevalence: str = "new"

    def to_dict(self):
        data=asdict(self)
        data["reasons"]=list(self.reasons or [])
        return data


class ReputationEngine:
    """Privacy-first local file reputation.

    v0.4 adds certificate context and device-local prevalence. No filename,
    hash, certificate or endpoint is uploaded anywhere by this engine.
    """
    def __init__(self,db: Database | None = None):
        self.db=db or Database()
        self._observed_pairs=set()
        self._observation_cache={}

    def _authenticode(self,path: Path) -> tuple[str,str]:
        # Compatibility seam used by existing tests/monkeypatches.
        details = self._authenticode_details(path)
        return details.status, details.publisher

    def _authenticode_details(self,path: Path) -> AuthenticodeDetails:
        return inspect_authenticode_details(path)

    @staticmethod
    def _prevalence(observation: dict) -> str:
        paths=int(observation.get("path_count") or 0)
        if paths >= 5:
            return "common"
        if paths >= 2:
            return "seen"
        return "new"

    @staticmethod
    def _from_cached(row, observation: dict) -> ReputationResult:
        return ReputationResult(
            signature_status=str(row["signature_status"] or ""),
            publisher=str(row["publisher"] or ""),
            local_trust=str(row["local_trust"] or "unknown"),
            issuer=str(row["issuer"] or "") if "issuer" in row.keys() else "",
            thumbprint=str(row["thumbprint"] or "") if "thumbprint" in row.keys() else "",
            valid_from=str(row["valid_from"] or "") if "valid_from" in row.keys() else "",
            valid_to=str(row["valid_to"] or "") if "valid_to" in row.keys() else "",
            timestamp_signer=str(row["timestamp_signer"] or "") if "timestamp_signer" in row.keys() else "",
            status_message=str(row["status_message"] or "") if "status_message" in row.keys() else "",
            first_seen=str(observation.get("first_seen") or ""),
            last_seen=str(observation.get("last_seen") or ""),
            observations=int(observation.get("observations") or 0),
            path_count=int(observation.get("path_count") or 0),
            cached=True,
        )

    def _observe(self, sha256: str, path: str, publisher: str = "") -> dict:
        try:
            canonical=str(Path(path).resolve())
        except Exception:
            canonical=str(path)
        key=(str(sha256 or "").casefold(),canonical.casefold())
        if key in self._observed_pairs:
            return dict(self._observation_cache.get(key[0]) or {})
        observation=self.db.observe_file_reputation(sha256,path,publisher)
        self._observed_pairs.add(key)
        self._observation_cache[key[0]]=dict(observation or {})
        return observation

    def assess_file(
        self,
        path: str | Path,
        sha256: str,
        *,
        base_score: int = 0,
        force_signature: bool = False,
    ) -> ReputationResult:
        p=Path(path)
        try:
            st=p.stat()
        except OSError:
            return ReputationResult()

        cached=self.db.get_file_reputation(str(p),st.st_mtime_ns,st.st_size,sha256=sha256)
        if cached:
            observation=self._observe(sha256,str(p),str(cached["publisher"] or ""))
            result=self._from_cached(cached, observation)
            return self._score(p,result)

        local_trust="unknown"
        details=AuthenticodeDetails()

        # Path/hash allowlist is checked before costly signature inspection.
        if self.db.is_allowlisted(str(p),sha256):
            local_trust="allowlisted"
        else:
            sensitive_location=any(x in str(p).casefold() for x in SENSITIVE_LOCATIONS)
            should_query=(
                p.suffix.casefold() in SIGNED_EXTENSIONS
                and (force_signature or int(base_score)>=10 or sensitive_location)
            )
            if should_query:
                # Respect the old monkeypatch seam when tests replace _authenticode.
                method=getattr(self,"_authenticode")
                func=getattr(method,"__func__",None)
                if func is not ReputationEngine._authenticode:
                    status,publisher=method(p)
                    details=AuthenticodeDetails(status=status,publisher=publisher)
                else:
                    details=self._authenticode_details(p)

            # Publisher trust is only valid when Windows says the signature is valid.
            if details.status=="Valid" and details.publisher and self.db.is_allowlisted(str(p),sha256,details.publisher):
                local_trust="allowlisted"

        self.db.upsert_file_reputation(
            path=str(p),
            mtime_ns=st.st_mtime_ns,
            size=st.st_size,
            sha256=sha256,
            signature_status=details.status,
            publisher=details.publisher,
            local_trust=local_trust,
            issuer=details.issuer,
            thumbprint=details.thumbprint,
            valid_from=details.valid_from,
            valid_to=details.valid_to,
            timestamp_signer=details.timestamp_signer,
            status_message=details.status_message,
        )
        observation=self._observe(sha256,str(p),details.publisher)
        result=ReputationResult(
            signature_status=details.status,
            publisher=details.publisher,
            local_trust=local_trust,
            issuer=details.issuer,
            thumbprint=details.thumbprint,
            valid_from=details.valid_from,
            valid_to=details.valid_to,
            timestamp_signer=details.timestamp_signer,
            status_message=details.status_message,
            first_seen=str(observation.get("first_seen") or ""),
            last_seen=str(observation.get("last_seen") or ""),
            observations=int(observation.get("observations") or 0),
            path_count=int(observation.get("path_count") or 0),
        )
        return self._score(p,result)

    def _score(self,p: Path,result: ReputationResult) -> ReputationResult:
        reasons=[]
        delta=0
        status=result.signature_status
        publisher=result.publisher
        local_trust=result.local_trust
        prevalence=self._prevalence({"path_count":result.path_count,"observations":result.observations})
        result.prevalence=prevalence

        if local_trust=="allowlisted":
            reasons.append("File presente nella reputazione locale attendibile")
        elif status=="Valid":
            reasons.append("Firma Authenticode valida"+(f" · {publisher}" if publisher else ""))
            if result.timestamp_signer:
                reasons.append("Firma con timestamp Authenticode")
        elif status=="NotSigned":
            delta += 4
            reasons.append("Eseguibile senza firma Authenticode")
        elif status and status not in {"Unsupported","UnknownError"}:
            delta += 15
            reasons.append(f"Firma Authenticode non valida: {status}")

        sensitive_location=any(x in str(p).casefold() for x in SENSITIVE_LOCATIONS)
        if prevalence=="new" and sensitive_location and status in {"NotSigned","UnknownError",""} and local_trust!="allowlisted":
            delta += 4
            reasons.append("File nuovo su questo dispositivo in percorso ad alto rischio")
        elif prevalence=="common":
            reasons.append("File già osservato in più percorsi locali")

        result.score_delta=min(25,delta)
        result.reasons=list(dict.fromkeys(reasons))
        return result
