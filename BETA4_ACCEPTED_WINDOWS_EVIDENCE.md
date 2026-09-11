# BC Sentinel v0.11.0-beta.4 — Accepted Windows Evidence

Status: **ACCEPTED / PASS**

## Frozen checkpoint

```text
checkpoint/v011-beta4-b45-pass
823ec10ff20157661e66418ac977c0827a654e29
```

This checkpoint is immutable. It includes the accepted B4-5 implementation plus the reproducible bootstrap used for the authoritative Windows run.

## Authoritative B4-5 Windows run

- Regression suite: **198 passed**.
- PyInstaller: **6.22.2** on Python **3.12.10** / Windows 11 build 26200.
- Hardened onedir build: **attempt 1/3 PASS**, exit code 0.
- Built executable SHA-256:

```text
8d14d89ea0abb773f17aafeec1edc995c7b25fb475687351a954ec370b369c58
```

- Built artifact SHA matched the integrity manifest.
- `status` from the built executable: PASS.
- Forbidden `repair-execute`: refused as expected.
- Built `plan`: PASS.
- Built RR-3 guided `scan`: PASS.
- Built integrated certification: **RECOVERED** for the clean trusted fixture.
- RR-6 report SHA-256:

```text
ab563bf202a93499c6a29acb5edecae93982278b5b852fd303536746e73abf2f
```

- Beta4 session summary SHA-256:

```text
65070bb9103f2cf5b33a13ce8a8b81710dd32013ee4a77edf7d3d94911c59901
```

- Target remained byte-identical.
- No Windows service registered.
- Protected B2 service/realtime/EDR sources remained unchanged.
- No installer, service or driver requirement was introduced.
- No automatic repair path was introduced.
- Reimage/format remains available whenever integrity cannot be demonstrated.

## Accepted milestone chain

```text
B4-0  PASS / FROZEN  checkpoint/v011-beta4-b40-pass
B4-1  PASS / FROZEN  checkpoint/v011-beta4-b41-pass
B4-2  PASS / FROZEN  checkpoint/v011-beta4-b42-pass
B4-3  PASS / FROZEN  checkpoint/v011-beta4-b43-pass
B4-4  PASS / FROZEN  checkpoint/v011-beta4-b44-pass
B4-5  PASS / FROZEN  checkpoint/v011-beta4-b45-pass
```

## Beta4 conclusion

**v0.11.0-beta.4 Rescue Console is CLOSED / PASS.**

The accepted portable Console exposes the integrated Rescue workflow while preserving the frozen trust boundaries of Beta3 and B4-0 through B4-4. Any future work must branch from the frozen B4-5 checkpoint or from a later documentation-only closure commit; no accepted checkpoint may be moved.