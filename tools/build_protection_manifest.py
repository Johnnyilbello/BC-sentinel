from __future__ import annotations
import argparse
from pathlib import Path
from sentinel.service_hardening import write_integrity_manifest


def main():
    parser = argparse.ArgumentParser(description="Build BC Sentinel Protection immutable-file manifest")
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    path = write_integrity_manifest(args.root)
    print(path)


if __name__ == "__main__":
    main()
