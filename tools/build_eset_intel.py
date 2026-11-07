"""Rebuild the pinned BC research IOC bundle from GitHub text artifacts only."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import quote
from urllib.request import Request, urlopen


REVISION = "825b826c5cbffcc1e59c16581ffdf7d527e8b695"
SOURCE = "https://github.com/eset/malware-ioc"
WINDOWS_RULES = (
    "animalfarm/animalfarm.yar",
    "badiis/badiis.yar",
    "groundbait/prikormka.yar",
    "invisimole/invisimole.yar",
    "nukesped_lazarus/rich_headers_IconicPayloads_3CX.yar",
    "potao/PotaoNew.yara",
    "redline/redline.yar",
    "stantinko/stantinko.yar",
    "ta410/ta410.yar",
    "turla/carbon.yar",
    "turla/gazer.yar",
    "turla/turla-outlook.yar",
)
DESTINATION = Path(__file__).resolve().parents[1] / "sentinel" / "data" / "eset_ioc"
SHA256 = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)


def fetch(url, limit):
    request = Request(url, headers={"User-Agent": "BC-Sentinel-IOC-builder"})
    with urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Artifact exceeds its byte limit: {url}")
    return data


def artifact(entry):
    path = entry["path"]
    size = entry["size"]
    if not 0 <= size <= 1024 * 1024:
        raise ValueError(f"Unexpected artifact size: {path}")
    data = fetch(f"https://raw.githubusercontent.com/eset/malware-ioc/{REVISION}/{quote(path)}", size)
    git_blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
    if len(data) != size or git_blob != entry["sha"]:
        raise ValueError(f"Git blob identity mismatch: {path}")
    return path, data


def main():
    import yara

    commit = json.loads(fetch(f"https://api.github.com/repos/eset/malware-ioc/commits/{REVISION}", 1024 * 1024))
    if commit["sha"] != REVISION:
        raise ValueError("Unexpected upstream commit")
    tree_hash = commit["commit"]["tree"]["sha"]
    tree = json.loads(fetch(
        f"https://api.github.com/repos/eset/malware-ioc/git/trees/{tree_hash}?recursive=1", 1024 * 1024
    ))
    if tree["truncated"] or tree["sha"] != tree_hash:
        raise ValueError("Incomplete or mismatched upstream tree")
    selected = [
        entry for entry in tree["tree"] if entry["type"] == "blob" and
        (PurePosixPath(entry["path"]).name == "samples.sha256"
         or entry["path"] in (*WINDOWS_RULES, "LICENSE"))
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        assets = dict(pool.map(artifact, selected))
    catalog = {}
    for path in sorted(assets):
        if PurePosixPath(path).name != "samples.sha256":
            continue
        for line in assets[path].decode("utf-8-sig").splitlines():
            digest = line.strip()
            if not digest or digest.startswith("#"):
                continue
            if not SHA256.fullmatch(digest):
                raise ValueError(f"Unexpected hash entry in {path}")
            catalog.setdefault(digest.lower(), str(PurePosixPath(path).parent))
    rules = {f"eset_{i:02d}": assets[path].decode("utf-8-sig") for i, path in enumerate(WINDOWS_RULES)}
    yara.compile(sources=rules, includes=False)
    bundle = {
        "revision": REVISION,
        "source": SOURCE,
        "hashes": catalog,
        "rules": {path: rules[f"eset_{i:02d}"] for i, path in enumerate(WINDOWS_RULES)},
    }
    DESTINATION.mkdir(parents=True, exist_ok=True)
    (DESTINATION / "bundle.json").write_text(
        json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8", newline="\n",
    )
    (DESTINATION / "LICENSE.txt").write_bytes(assets["LICENSE"])
    print(f"{len(catalog)} unique SHA-256 entries, {len(rules)} rule sources")


if __name__ == "__main__":
    main()
