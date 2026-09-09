from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from sentinel.service_hardening import IntegrityVerifier
from sentinel.service_update import (
    apply_update_transaction,
    mark_transaction,
    recover_transaction,
    rollback_transaction,
    validate_update_source,
)


def _latest_transaction_journal(root: Path, *, newer_than: float) -> Path | None:
    try:
        candidates = [
            path for path in root.glob("BCU-*.json")
            if path.is_file() and path.stat().st_mtime >= newer_than - 1.0
        ]
    except OSError:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime, default=None)


def _verify_current(target: Path) -> dict:
    result = IntegrityVerifier(target).verify(require_signature=True, full=False)
    return {
        "target": str(target.resolve()),
        "passed": bool(result.ok),
        "integrity": result.to_dict(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Protection transactional update helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--source", required=True, type=Path)
    validate.add_argument("--target", required=True, type=Path)
    validate.add_argument("--mode", choices=("upgrade", "repair"), default="upgrade")

    apply = sub.add_parser("apply")
    apply.add_argument("--source", required=True, type=Path)
    apply.add_argument("--target", required=True, type=Path)
    apply.add_argument("--backup-root", required=True, type=Path)
    apply.add_argument("--mode", choices=("upgrade", "repair"), default="upgrade")

    rollback = sub.add_parser("rollback")
    rollback.add_argument("--journal", required=True, type=Path)

    recover = sub.add_parser("recover")
    recover.add_argument("--journal", required=True, type=Path)

    mark = sub.add_parser("mark")
    mark.add_argument("--journal", required=True, type=Path)
    mark.add_argument("--status", required=True)

    verify = sub.add_parser("verify-current")
    verify.add_argument("--target", required=True, type=Path)

    args = parser.parse_args()
    started = time.time()
    try:
        if args.cmd == "validate":
            result = validate_update_source(args.source, args.target, mode=args.mode).to_dict()
        elif args.cmd == "apply":
            result = apply_update_transaction(args.source, args.target, args.backup_root, mode=args.mode)
        elif args.cmd == "rollback":
            result = rollback_transaction(args.journal)
        elif args.cmd == "recover":
            result = recover_transaction(args.journal)
        elif args.cmd == "verify-current":
            result = _verify_current(args.target)
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result.get("passed") else 2
        else:
            result = mark_transaction(args.journal, args.status)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        payload = {
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
        if args.cmd == "apply":
            journal = _latest_transaction_journal(args.backup_root, newer_than=started)
            if journal is not None:
                payload["journal"] = str(journal.resolve())
        print(json.dumps(payload, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
