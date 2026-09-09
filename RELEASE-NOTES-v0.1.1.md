# BC Sentinel v0.1.1 — False-positive hardening

Changes:
- normal scans exclude BC Sentinel's own application/data/quarantine paths;
- EICAR detection now requires the exact harmless EICAR test file (optional CR/LF tolerated);
- source files, tests and documentation that merely mention EICAR are no longer classified as EICAR;
- EICAR no longer produces duplicate static + YARA reasons;
- duplicate alerts are suppressed by SHA-256 during a scan;
- real-time duplicate hash events are suppressed for 10 minutes;
- self-scanning is separated into `SelfIntegrityScanner`;
- UI labels use transparent backgrounds, removing the black rectangles;
- dashboard wording changed from `IL TUO PC È PROTETTO` to `BC SENTINEL È ATTIVO`;
- version bumped to 0.1.1.
