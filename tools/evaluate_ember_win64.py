"""Evaluate pinned upstream Win64 model on local ZIP byte ranges and challenge."""
import argparse
import hashlib
import io
import json
import math
import zipfile
from pathlib import Path

import lightgbm
import numpy
from thrember import PEFeatureExtractor


REPOSITORY = Path(__file__).resolve().parents[1]
ZIP_SIZE = 1176459716
CALIBRATION = "2024-09-22_2024-09-28_Win64_test.jsonl"
HOLDOUT = "2024-12-08_2024-12-14_Win64_test.jsonl"
RANGE_SHA256 = {
    "first": "5664f7abea168f05fcc05e58dd6236089e2a79419079281a0938dcfa55f58c2e",
    "last": "d4b509df97413662b35fc1467469352cf4bd7b20b3f7d86cd7415994304fd7ca",
    "tail": "eb8beae8cdd83dbb2f325048576ce5be80913291a929ea10b0ea6642edb84c8e",
}


def verified(path, expected):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"Unexpected SHA-256: {path.name}")
    return path


class ZipRanges(io.RawIOBase):
    def __init__(self, folder, prefix, offset):
        data = verified(folder / f"ember-win64-{prefix}.bin", RANGE_SHA256[prefix]).read_bytes()
        tail = verified(folder / "ember-win64-tail.bin", RANGE_SHA256["tail"]).read_bytes()
        tail_offset = ZIP_SIZE - len(tail)
        overlap = offset + len(data) - tail_offset
        if overlap > 0 and data[-overlap:] != tail[:overlap]:
            raise ValueError("ZIP ranges disagree")
        self.ranges = ((offset, data), (tail_offset, tail))
        self.position = 0

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        base = (0, self.position, ZIP_SIZE)[whence]
        self.position = base + offset
        return self.position

    def seekable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            size = ZIP_SIZE - self.position
        if size == 0:
            return b""
        for offset, data in self.ranges:
            start = self.position - offset
            if 0 <= start and start + size <= len(data):
                self.position += size
                return data[start:start + size]
        raise OSError(f"ZIP read outside fetched range: {self.position}+{size}")


def evaluate(archive, members, extractor, model, indicators, name):
    examples = {}
    batch = []
    keys = []
    excluded = {"unknown_label": 0, "duplicate": 0, "conflicting_label": 0}
    conflicting = set()

    def flush():
        if not batch:
            return
        values = model.predict(numpy.stack(batch), num_threads=1)
        if not numpy.isfinite(values).all():
            raise ValueError("Non-finite model scores")
        for key, value in zip(keys, values, strict=True):
            label, baseline = examples[key]
            examples[key] = label, baseline, float(value)
        keys.clear()
        batch.clear()

    for member in members:
        with archive.open(member) as stream:
            for line in stream:
                record = json.loads(line)
                if record["file_type"] != "Win64":
                    continue
                key = record["sha256"]
                label = record["label"]
                if label not in (0, 1):
                    excluded["unknown_label"] += 1
                    continue
                if key in conflicting:
                    excluded["conflicting_label"] += 1
                    continue
                if key in examples:
                    if examples[key][0] == label:
                        excluded["duplicate"] += 1
                    else:
                        flush()
                        del examples[key]
                        conflicting.add(key)
                        excluded["conflicting_label"] += 2
                    continue
                examples[key] = label, key in indicators
                batch.append(extractor.process_raw_features(record))
                keys.append(key)
                if len(batch) == 128:
                    flush()
                if len(examples) % 1000 == 0:
                    print(name, len(examples), flush=True)
    flush()
    print(json.dumps({name + "_excluded": excluded}), flush=True)
    return examples


def rates(examples, threshold):
    counts = {}
    for label, group in ((0, "benign"), (1, "malicious")):
        rows = [(ioc, score) for actual, ioc, score in examples.values() if actual == label]
        counts[group] = {
            "total": len(rows),
            "hash_matches": sum(ioc for ioc, score in rows),
            "model_flags": sum(score >= threshold for ioc, score in rows),
            "combined_flags": sum(ioc or score >= threshold for ioc, score in rows),
        }
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_folder", type=Path, help="Folder containing the pinned model and ZIP ranges")
    folder = parser.parse_args().data_folder
    model_path = verified(
        folder / "EMBER2024_Win64-e5b945dd.model",
        "8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b",
    )
    challenge = verified(
        folder / "EMBER2024-challenge-3d23ef.zip",
        "dd215997b10596e4397d2b305d54afe9678e91e3051918262f0172b36e40baf1",
    )
    model = lightgbm.Booster(model_file=str(model_path))
    extractor = PEFeatureExtractor()
    if model.num_feature() != extractor.dim:
        raise ValueError("Model and extractor dimensions differ")
    intel_path = REPOSITORY / "sentinel/data/eset_ioc/bundle.json"
    indicators = json.loads(intel_path.read_bytes())["hashes"]
    with zipfile.ZipFile(ZipRanges(folder, "first", 0)) as archive:
        calibration = evaluate(archive, [CALIBRATION], extractor, model, indicators, "calibration")
    benign = sorted((score for label, ioc, score in calibration.values() if label == 0), reverse=True)
    threshold = max(.99, math.nextafter(benign[len(benign) // 1000], math.inf))
    print(json.dumps({"threshold": threshold, "calibration": rates(calibration, threshold)}), flush=True)
    with zipfile.ZipFile(ZipRanges(folder, "last", 1076659619)) as archive:
        holdout = evaluate(archive, [HOLDOUT], extractor, model, indicators, "holdout")
    overlap = calibration.keys() & holdout.keys()
    for key in overlap:
        del holdout[key]
    print(json.dumps({"holdout_excluded_calibration_overlap": len(overlap)}), flush=True)
    print(json.dumps({"holdout": rates(holdout, threshold)}), flush=True)
    with zipfile.ZipFile(challenge) as archive:
        members = [name for name in archive.namelist() if name.endswith(".jsonl")]
        evasive = evaluate(archive, members, extractor, model, indicators, "challenge")
    if not evasive:
        raise ValueError("Empty Win64 challenge")
    print(json.dumps({"challenge": rates(evasive, threshold)}), flush=True)


if __name__ == "__main__":
    main()
