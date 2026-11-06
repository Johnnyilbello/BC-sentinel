"""User-confirmed isolation of exact BC catalog matches on Windows."""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
from uuid import uuid4

from sentinel.guided_resolution_real_file_execution import assess_target_eligibility, allowed_user_roots
from sentinel.rescue_offline_scanner import _validate_local_path


MAX_BYTES = 16 * 1024 * 1024
MAX_HEADER_BYTES = 256 * 1024
MAX_ENTRIES = 256
MAGIC = b"BCQ1"
TOKEN = re.compile(r"[0-9a-f]{32}")
INVALID_HANDLE = ctypes.c_void_p(-1).value


class _Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.c_void_p)]


class _StreamData(ctypes.Structure):
    _fields_ = [("size", ctypes.c_longlong), ("name", wintypes.WCHAR * 296)]


class _AttributeTag(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


def _bind(dll, name, restype, *argtypes):
    function = getattr(dll, name)
    function.restype, function.argtypes = restype, argtypes
    return function


class _Windows:
    def __init__(self):
        if os.name != "nt":
            raise OSError("La quarantena BC richiede Windows.")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        crypto = ctypes.WinDLL("crypt32", use_last_error=True)
        ptr = ctypes.c_void_p
        handle, dword, boolean, string = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR
        self.create = _bind(kernel, "CreateFileW", handle, string, dword, dword, ptr, dword, dword, handle)
        self.close = _bind(kernel, "CloseHandle", boolean, handle)
        self.final_path = _bind(kernel, "GetFinalPathNameByHandleW", dword, handle, wintypes.LPWSTR, dword, dword)
        self.info = _bind(kernel, "GetFileInformationByHandleEx", boolean, handle, ctypes.c_int, ptr, dword)
        self.set_info = _bind(kernel, "SetFileInformationByHandle", boolean, handle, ctypes.c_int, ptr, dword)
        self.first_stream = _bind(kernel, "FindFirstStreamW", handle, string, ctypes.c_int, ptr, dword)
        self.next_stream = _bind(kernel, "FindNextStreamW", boolean, handle, ptr)
        self.close_search = _bind(kernel, "FindClose", boolean, handle)
        self.free = _bind(kernel, "LocalFree", ptr, ptr)
        self.protect = _bind(crypto, "CryptProtectData", boolean, ptr, string, ptr, ptr, ptr, dword, ptr)
        self.unprotect = _bind(crypto, "CryptUnprotectData", boolean, ptr, ptr, ptr, ptr, ptr, dword, ptr)

    def crypt(self, data, *, decrypt=False):
        buffer = ctypes.create_string_buffer(data)
        source = _Blob(len(data), ctypes.addressof(buffer))
        result = _Blob()
        function = self.unprotect if decrypt else self.protect
        if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(result.data, result.size)
        finally:
            self.free(result.data)

    def verify_handle(self, handle, path, *, directory=False):
        output = ctypes.create_unicode_buffer(32768)
        length = self.final_path(handle, output, len(output), 0)
        if not 0 < length < len(output):
            raise OSError("Impossibile verificare il percorso aperto.")
        actual = output.value.removeprefix("\\\\?\\")
        if os.path.normcase(actual) != os.path.normcase(str(path)):
            raise ValueError("Il percorso è cambiato durante l’operazione.")
        info = _AttributeTag()
        if not self.info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
            raise ValueError("Collegamento o tipo di file non supportato.")

    @contextmanager
    def directory_lock(self, path):
        _validate_local_path(path)
        handle = self.create(str(path), 0x80, 3, None, 3, 0x02200000, None)
        if handle == INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.verify_handle(handle, path, directory=True)
            yield
        finally:
            self.close(handle)

    @contextmanager
    def locked_file(self, path):
        import msvcrt

        handle = self.create(str(path), 0x80010000, 0, None, 3, 0x00200000, None)
        if handle == INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.verify_handle(handle, path)
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            self.close(handle)
            raise
        with os.fdopen(fd, "rb") as stream:
            if os.fstat(stream.fileno()).st_nlink != 1:
                raise ValueError("Il file ha più collegamenti fisici.")
            yield handle, stream

    def require_no_alternate_streams(self, path):
        data = _StreamData()
        search = self.first_stream(str(path), 0, ctypes.byref(data), 0)
        if search == INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if data.name != "::$DATA" or self.next_stream(search, ctypes.byref(data)):
                raise ValueError("Il file contiene flussi NTFS aggiuntivi. Isolamento rifiutato per preservarli.")
            if ctypes.get_last_error() != 38:  # ERROR_HANDLE_EOF
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.close_search(search)

    def remove_open_file(self, handle):
        delete = ctypes.c_ubyte(1)
        if not self.set_info(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
            raise ctypes.WinError(ctypes.get_last_error())


@dataclass(frozen=True)
class QuarantineEntry:
    token: str
    original: str
    sha256: str
    size: int


class BCQuarantine:
    def __init__(self, root, *, user_profile=None):
        self.root = Path(os.path.abspath(root))
        self.user_profile = user_profile
        self.incomplete_listing = False

    def _entry_path(self, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise ValueError("Identificativo di quarantena non valido.")
        return self.root / f"{token}.bcq"

    def _read_header(self, api, stream, token):
        prefix = stream.read(8)
        if len(prefix) != 8 or prefix[:4] != MAGIC:
            raise ValueError("Formato quarantena non valido.")
        size = struct.unpack("<I", prefix[4:])[0]
        if not 1 <= size <= MAX_HEADER_BYTES:
            raise ValueError("Intestazione quarantena non valida.")
        encrypted = stream.read(size)
        if len(encrypted) != size:
            raise ValueError("Intestazione quarantena incompleta.")
        fields = json.loads(api.crypt(encrypted, decrypt=True))
        if not isinstance(fields, dict) or fields.keys() != QuarantineEntry.__dataclass_fields__.keys():
            raise ValueError("Dati di quarantena non validi.")
        entry = QuarantineEntry(**fields)
        if (entry.token != token or not isinstance(entry.original, str) or not isinstance(entry.sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry.sha256)
                or type(entry.size) is not int or not 0 <= entry.size <= MAX_BYTES):
            raise ValueError("Dati di quarantena non validi.")
        return entry

    def entries(self):
        self.incomplete_listing = False
        if not self.root.exists():
            return []
        api = _Windows()
        entries = []
        with api.directory_lock(self.root), os.scandir(self.root) as items:
            for index, item in enumerate(items):
                if index >= MAX_ENTRIES * 4 or len(entries) >= MAX_ENTRIES:
                    self.incomplete_listing = True
                    break
                token = Path(item.name).stem
                if not item.name.endswith(".bcq") or not TOKEN.fullmatch(token):
                    continue
                try:
                    _validate_local_path(Path(item.path))
                    with open(item.path, "rb") as stream:
                        entries.append(self._read_header(api, stream, token))
                except (OSError, ValueError, TypeError):
                    self.incomplete_listing = True
                    continue
        return entries

    def isolate(self, target, expected_sha256):
        path = Path(os.path.abspath(target))
        _validate_local_path(path)
        decision = assess_target_eligibility(path, user_profile=self.user_profile)
        if not decision["eligible"]:
            raise ValueError("Isolamento consentito solo per file idonei in Desktop, Documenti o Download.")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("Impronta SHA-256 non valida.")
        api = _Windows()
        _validate_local_path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        entry_path = self._entry_path(uuid4().hex)
        with api.directory_lock(self.root), api.directory_lock(path.parent), api.locked_file(path) as (handle, stream):
            api.require_no_alternate_streams(path)
            data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != expected_sha256:
                raise ValueError("Il file è cambiato o supera il limite di 16 MiB.")
            entry = QuarantineEntry(entry_path.stem, str(path), expected_sha256, len(data))
            header = api.crypt(json.dumps(entry.__dict__, ensure_ascii=False).encode("utf-8"))
            encrypted = api.crypt(data)
            temporary = entry_path.with_suffix(".partial")
            created = False
            try:
                with temporary.open("xb") as out:
                    created = True
                    out.write(MAGIC + struct.pack("<I", len(header)) + header + encrypted)
                    out.flush()
                    os.fsync(out.fileno())
                os.rename(temporary, entry_path)  # Windows refuses an existing destination.
                created = False
                with entry_path.open("rb") as saved:
                    saved_entry = self._read_header(api, saved, entry.token)
                    saved_data = saved.read(MAX_BYTES + MAX_HEADER_BYTES + 1)
                    if saved_entry != entry or len(saved_data) > MAX_BYTES + MAX_HEADER_BYTES or api.crypt(saved_data, decrypt=True) != data:
                        raise OSError("La copia cifrata non corrisponde al file originale.")
                api.require_no_alternate_streams(path)
                api.remove_open_file(handle)
            finally:
                if created:
                    temporary.unlink(missing_ok=True)
        if os.path.lexists(path):
            raise OSError("Copia cifrata salvata, ma il percorso originale risulta ancora presente.")
        return entry

    def restore(self, token):
        api = _Windows()
        entry_path = self._entry_path(token)
        with api.directory_lock(self.root):
            _validate_local_path(entry_path)
            with entry_path.open("rb") as stream:
                entry = self._read_header(api, stream, token)
                encrypted = stream.read(MAX_BYTES + MAX_HEADER_BYTES + 1)
            if len(encrypted) > MAX_BYTES + MAX_HEADER_BYTES:
                raise ValueError("Contenuto quarantena oltre il limite.")
            data = api.crypt(encrypted, decrypt=True)
            if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.sha256:
                raise ValueError("La copia cifrata non corrisponde al file registrato.")
            path = Path(entry.original)
            if (not path.is_absolute() or ".." in path.parts or ":" in str(path)[len(path.drive):]
                    or not any(path.is_relative_to(root) for root in allowed_user_roots(self.user_profile))):
                raise ValueError("Percorso di ripristino non consentito.")
            with api.directory_lock(path.parent):
                if os.path.lexists(path):
                    raise FileExistsError("Il percorso originale è già occupato.")
                temporary = path.parent / f".bc-{uuid4().hex}.partial"
                created = False
                try:
                    with temporary.open("xb") as out:
                        created = True
                        out.write(data)
                        out.flush()
                        os.fsync(out.fileno())
                    os.rename(temporary, path)
                    created = False
                    _validate_local_path(path)
                    with path.open("rb") as restored:
                        if restored.read(MAX_BYTES + 1) != data:
                            raise OSError("Ripristino non verificato. La copia cifrata resta nel deposito.")
                finally:
                    if created:
                        temporary.unlink(missing_ok=True)
            try:
                entry_path.unlink()
            except OSError as exc:
                raise OSError("File ripristinato, ma la copia cifrata resta nel deposito.") from exc
        return entry
