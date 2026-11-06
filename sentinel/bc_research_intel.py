"""Pinned public research indicators bundled with the desktop scanner."""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


ROOT = Path(__file__).with_name("data") / "eset_ioc"
REVISION = "825b826c5cbffcc1e59c16581ffdf7d527e8b695"
BUNDLE_SHA256 = "4c77ee4e44e80f53d4b682c851853620bd07075343a0684e3777d4b60d8e1c2a"
IOC_COUNT = 6138
SOURCE = "ESET Research · malware-ioc"


@dataclass(frozen=True)
class ResearchIntel:
    hashes: Mapping[str, str]
    rules: object


@lru_cache(maxsize=1)
def load():
    with (ROOT / "bundle.json").open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != BUNDLE_SHA256:
        raise ValueError("L’impronta del catalogo integrato non corrisponde alla build.")
    bundle = json.loads(data)
    if bundle["revision"] != REVISION or len(bundle["hashes"]) != IOC_COUNT:
        raise ValueError("Revisione del catalogo integrato inattesa.")
    import yara

    # Give each upstream file its own namespace so rule identifiers and
    # private references retain the same scope as in the original file.
    rules = yara.compile(sources={
        f"eset_{index:02d}": source for index, source in enumerate(bundle["rules"].values())
    }, includes=False)
    return ResearchIntel(MappingProxyType(bundle["hashes"]), rules)
