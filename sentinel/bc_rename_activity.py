"""Advisory signal for mass extension changes observed in a watched folder."""
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from time import monotonic


DOCUMENT_EXTENSIONS = frozenset({
    ".csv", ".doc", ".docx", ".jpeg", ".jpg", ".odt", ".ods", ".pdf",
    ".png", ".ppt", ".pptx", ".rtf", ".txt", ".xls", ".xlsx",
})
WINDOW_SECONDS = 12
MIN_RENAMES = 15
MAX_TRACKED_PATHS = 512


@dataclass(frozen=True)
class RenameAlert:
    extension: str
    distinct_renames: int
    window_seconds: int

    def description(self):
        return (
            f"{self.distinct_renames} documenti rinominati verso {self.extension!r} "
            f"in {self.window_seconds} s. Verifica se hai avviato un’operazione in blocco."
        )


class RenameActivity:
    def __init__(self, root: Path, *, clock=monotonic):
        self.root = root
        self.clock = clock
        self._moves = OrderedDict()
        self._quiet_until = 0.0

    def observe(self, source: Path, destination: Path):
        if not source.is_relative_to(self.root) or not destination.is_relative_to(self.root):
            return None
        old = source.suffix.casefold()
        new = destination.suffix.casefold()
        if old not in DOCUMENT_EXTENSIONS or not new or new in DOCUMENT_EXTENSIONS:
            return None

        now = self.clock()
        while self._moves and next(iter(self._moves.values()))[0] <= now - WINDOW_SECONDS:
            self._moves.popitem(last=False)
        self._moves[destination] = (now, source, new)
        self._moves.move_to_end(destination)
        if len(self._moves) > MAX_TRACKED_PATHS:
            self._moves.popitem(last=False)
        if now < self._quiet_until:
            return None

        distinct_sources = {previous for _, previous, suffix in self._moves.values() if suffix == new}
        if len(distinct_sources) >= MIN_RENAMES:
            self._quiet_until = now + 60
            return RenameAlert(new, len(distinct_sources), WINDOW_SECONDS)
        return None
