"""Bounded, static indicators of PowerShell download-to-evaluation flows."""
import base64
import binascii
import re
import struct


MAX_SCRIPT_BYTES = 256 * 1024
SCRIPT_SUFFIXES = frozenset({".ps1", ".psm1", ".cmd", ".bat", ".lnk"})
_SHELL_LINK_HEADER = bytes.fromhex("4c0000000114020000000000c000000000000046")
_DOWNLOAD = frozenset({"invoke-webrequest", "invoke-restmethod", "iwr", "irm"})
_EVALUATE = frozenset({"invoke-expression", "iex"})
_TOKEN = re.compile(
    r"(?P<separator>[\r\n;])|(?P<space>[^\S\r\n]+)|"
    r"(?P<comment>\#[^\r\n]*)|"
    r"""(?P<quoted>'(?:[^'\r\n]|'')*'|"(?:[^"\x60\r\n]|\x60[^\r\n])*")|"""
    r"(?P<url>https?://[^\s'\";|(){}]+)|"
    r"(?P<qualified>Microsoft\.PowerShell\.Utility\\(?:Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod)\b)|"
    r"(?P<word>\$[A-Za-z_]\w*|[A-Za-z_][\w.-]*)|(?P<other>.)",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\x22]+", re.IGNORECASE)
_ENCODED = re.compile(
    r"""(?i)(?:^|\s)-(?:encodedcommand|enc|ec|e)\s+["']?([A-Za-z0-9+/]{12,8192}={0,2})(?=["'\s]|$)"""
)
_CARRIER = re.compile(
    r'''(?im)^[ \t]*@?(?:call[ \t]+)?(?:"[^"\r\n]*\\(?:powershell|pwsh)\.exe"|(?:powershell|pwsh)(?:\.exe)?)[ \t]+([^\r\n]*)'''
)
_COMMAND_POSITIONS = frozenset({"(", "=", "{", "|", "&"})


def _text(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\0" in data[:256]:
        sample = data[:256]
        if len(data) % 2 == 0 and sample[1::2].count(0) >= len(sample) // 4 and 0 not in sample[::2]:
            return data.decode("utf-16-le", errors="replace")
        raise ValueError("codifica script non riconosciuta")
    return data.decode("utf-8-sig", errors="replace")


def _statements(text):
    """Yield approximate lexical statements, ignoring quoted prose and comments."""
    tokens = []
    position = 0
    while position < len(text):
        if text.startswith("<#", position):
            end = text.find("#>", position + 2)
            position = len(text) if end < 0 else end + 2
            continue
        if text.startswith(("@'", '@"'), position):
            quote = text[position + 1]
            end = text.find("\n" + quote + "@", position + 2)
            position = len(text) if end < 0 else end + 3
            continue
        # PowerShell treats a backtick immediately before a newline as continuation.
        if text.startswith("`\r\n", position):
            position += 3
            continue
        if text.startswith("`\n", position):
            position += 2
            continue
        token = _TOKEN.match(text, position)
        if token is None:
            position += 1
            continue
        position = token.end()
        kind, value = token.lastgroup, token.group().casefold()
        if kind == "separator":
            if tokens:
                yield tokens
            tokens = []
        elif kind == "quoted":
            tokens.append("<url>" if _URL.fullmatch(value[1:-1]) else "<string>")
        elif kind == "url":
            tokens.append("<url>")
        elif kind == "qualified":
            tokens.append(value.rsplit("\\", 1)[-1])
        elif kind not in {"space", "comment"}:
            tokens.append(value)
    if tokens:
        yield tokens


def _download_to_eval(text):
    downloaded = set()
    for tokens in _statements(text):
        commands = [
            index for index, token in enumerate(tokens)
            if token in _DOWNLOAD | _EVALUATE and (index == 0 or tokens[index - 1] in _COMMAND_POSITIONS)
        ]
        fetches = "<url>" in tokens and any(tokens[index] in _DOWNLOAD for index in commands)
        evaluates = [index for index in commands if tokens[index] in _EVALUATE]
        if evaluates and (fetches or any(var in downloaded for var in tokens[evaluates[0] + 1:])):
            return True
        if len(tokens) >= 3 and tokens[0].startswith("$") and tokens[1] == "=":
            variable = tokens[0]
            if fetches and len(downloaded) < 64:
                downloaded.add(variable)
            else:
                downloaded.discard(variable)
    return False


def _encoded_flow(arguments):
    for index, match in enumerate(_ENCODED.finditer(arguments)):
        if index == 8:
            break
        try:
            decoded = base64.b64decode(match[1], validate=True).decode("utf-16-le")
        except (binascii.Error, UnicodeError):
            continue
        if _download_to_eval(decoded):
            return True
    return False


def _link_arguments(data):
    if len(data) < 76 or not data.startswith(_SHELL_LINK_HEADER):
        raise ValueError("intestazione collegamento non valida")
    flags = struct.unpack_from("<I", data, 20)[0]
    if not flags & 0x20:
        return ""
    offset = 76
    if flags & 1:
        offset += 2 + struct.unpack_from("<H", data, offset)[0]
    if flags & 2:
        length = struct.unpack_from("<I", data, offset)[0]
        if length < 28:
            raise ValueError("LinkInfo non valido")
        offset += length
    unicode = bool(flags & 0x80)
    for bit in (4, 8, 16, 32):
        if flags & bit:
            length = struct.unpack_from("<H", data, offset)[0] * (2 if unicode else 1)
            offset += 2
            end = offset + length
            if end > len(data):
                raise ValueError("StringData incompleto")
            if bit == 32:
                return data[offset:end].decode("utf-16-le" if unicode else "cp1252", errors="replace")
            offset = end
    return ""


def inspect_script(data, suffix):
    """Return advisory signal names. The input is never sent to an interpreter."""
    if suffix not in SCRIPT_SUFFIXES:
        return ()
    if len(data) > MAX_SCRIPT_BYTES:
        raise ValueError("limite analisi script: 256 KiB")
    if suffix == ".lnk":
        try:
            arguments = _link_arguments(data)
        except struct.error as exc:
            raise ValueError("collegamento incompleto") from exc
        return ("Collegamento con comando codificato di download ed esecuzione",) if _encoded_flow(arguments) else ()
    text = _text(data)
    if suffix in {".ps1", ".psm1"} and _download_to_eval(text):
        return ("PowerShell: contenuto remoto passato a valutazione dinamica",)
    if suffix in {".cmd", ".bat"} and any(_encoded_flow(match[1]) for match in _CARRIER.finditer(text)):
        return ("Batch: comando PowerShell codificato di download ed esecuzione",)
    return ()
