from __future__ import annotations

"""B6-3.4 stabilization guard for risk-prioritized Smart Scan planning.

The historical StaticScanner intentionally refuses BC Sentinel self-managed
paths. A broad configured root such as Downloads can contain the pinned
historical runtime itself, so the Smart Scan planner must not schedule files
that the authoritative scanner is guaranteed to refuse.

This module wraps the B6-3.4 provider without weakening fail-closed semantics:
only the exact pinned runtime root is excluded from candidate planning. Other
BC Sentinel-looking paths and arbitrary temporary files remain scannable.
"""

import os
from pathlib import Path
from time import time
from typing import Any, Iterable

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_scope as scope

GUARD_ID = "exclude_pinned_runtime_root_v1"
PROVENANCE_SUFFIX = "+exclude_pinned_runtime_root_v1"


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(str(path))))


def _is_within(path: Path, root: Path) -> bool:
    path_key = _path_key(path)
    root_key = _path_key(root)
    try:
        return os.path.commonpath((path_key, root_key)) == root_key
    except (ValueError, OSError):
        return False


def select_scope_excluding(
    roots: Iterable[Path],
    excluded_roots: Iterable[Path],
    policy: scope.ScopePolicy | None = None,
) -> tuple[scope.ScopeSelection, int]:
    """Build the normal B6-3.4 scope after removing exact guarded subtrees.

    Discovery remains read-only and uses the same B6-3.4 candidate/scoring
    implementation. Exclusion happens before the global file/byte budget is
    allocated, so a self-managed candidate cannot consume a Smart Scan slot.
    """

    policy = policy or scope.ScopePolicy.from_environment()
    excluded = tuple(Path(item) for item in excluded_roots)
    now = time()
    discovered: list[tuple[Path, list[scope.Candidate], int, list[str], int]] = []

    for raw_root in roots:
        root = Path(raw_root)
        raw_pool, skipped_oversize, errors = scope._discover_root(root, policy, now)
        pool = [item for item in raw_pool if not any(_is_within(item.path, blocked) for blocked in excluded)]
        excluded_count = len(raw_pool) - len(pool)
        discovered.append((root, pool, skipped_oversize, errors, excluded_count))

    all_candidates = [item for _, pool, _, _, _ in discovered for item in pool]
    all_candidates.sort(key=lambda item: (-item.score, -item.mtime, str(item.path).casefold()))

    selected_paths: set[str] = set()
    used_bytes = 0
    for item in all_candidates:
        if len(selected_paths) >= policy.max_files:
            break
        if selected_paths and used_bytes + item.size > policy.max_total_bytes:
            continue
        if not selected_paths and item.size > policy.max_total_bytes:
            continue
        selected_paths.add(_path_key(item.path))
        used_bytes += item.size

    groups: list[scope.ScopeGroup] = []
    total_excluded = 0
    for root, pool, skipped_oversize, errors, excluded_count in discovered:
        selected = tuple(item for item in pool if _path_key(item.path) in selected_paths)
        groups.append(
            scope.ScopeGroup(
                root=root,
                selected=selected,
                candidate_pool_count=len(pool),
                skipped_oversize=skipped_oversize,
                skipped_budget=max(0, len(pool) - len(selected)),
                walk_errors=tuple(errors[:20]),
            )
        )
        total_excluded += excluded_count

    return scope.ScopeSelection(tuple(groups), policy), total_excluded


class RuntimeGuardedRiskPrioritizedProvider(scope.RiskPrioritizedStaticScannerProvider):
    def capabilities(self):
        raw = dict(super().capabilities())
        raw.update(
            {
                "scope_guard": GUARD_ID,
                "self_managed_runtime_excluded": True,
            }
        )
        raw["provider_provenance"] = str(raw.get("provider_provenance") or "") + PROVENANCE_SUFFIX
        return raw

    def build_plan(self) -> smart.SmartScanPlan:
        roots = tuple(Path(item) for item in getattr(self._base, "_roots", ()))
        excluded_roots = (Path(self._binding.root),) if self._binding is not None else ()
        selection, excluded_count = select_scope_excluding(roots, excluded_roots)
        self._last_selection = selection
        self._planned_files = {}

        caps = dict(self.capabilities())
        provenance = str(caps["provider_provenance"])
        checks: list[smart.SmartScanCheck] = []
        for index, group in enumerate(selection.groups, start=1):
            check_id = f"smart_scope_{index:02d}"
            files = tuple(item.path for item in group.selected)
            self._planned_files[check_id] = files
            checks.append(
                smart.SmartScanCheck(
                    check_id=check_id,
                    label=f"Priority Smart Scan — {group.root}",
                    purpose="Inspect the highest-risk recent executable, script, persistence, macro and container candidates in this configured root.",
                    available=True,
                    provenance=provenance,
                    work_units=max(1, len(files)),
                    raw={
                        **group.to_dict(),
                        "scope_mode": scope.MODE,
                        "full_filesystem_coverage": False,
                        "scope_guard": GUARD_ID,
                    },
                )
            )

        raw = selection.to_dict()
        raw.update(
            {
                "scope_guard": GUARD_ID,
                "excluded_self_managed_roots": [str(item) for item in excluded_roots],
                "excluded_candidate_count": excluded_count,
            }
        )
        return smart.SmartScanPlan(
            provider_name=str(caps.get("provider_name") or "BC Sentinel StaticScanner live adapter"),
            provider_profile=scope.PROFILE,
            provider_provenance=provenance,
            checks=tuple(checks),
            raw=raw,
        )


def wrap_provider(module: Any, base_provider: Any) -> Any:
    """Wrap an accepted pinned runtime only when scan_file is proven callable."""

    base_caps = dict(base_provider.capabilities())
    if not (base_caps.get("available") is True and base_caps.get("accepted") is True):
        return base_provider
    ok, evidence = scope._probe_scan_file(module, base_provider)
    if not ok:
        return base_provider
    return RuntimeGuardedRiskPrioritizedProvider(module, base_provider, evidence)
