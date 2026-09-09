# BC Sentinel v0.1.6 — Ransomware Hardening

## False-positive hardening
- ransomware scoring is now separated from ordinary real-time static scanning;
- Temp and AppData remain watched for suspicious executable/script files, but
  filesystem churn there does not feed the ransomware burst heuristic;
- ransomware-protected folders default to Desktop, Documents and Pictures;
- 30-second startup grace period prevents installer/Python initialization churn
  from triggering the ransomware engine;
- `.venv`, `venv`, `node_modules`, `.git`, `build`, `dist` and `__pycache__`
  trees are ignored by the ransomware burst engine;
- raw modification/rename/delete bursts alone are capped at a non-alerting
  SUSPICIOUS classification;
- HIGH/CRITICAL user alerts require an independent strong signal:
  canary modification, mass extension mutation or entropy spike;
- ransomware alert cooldown increased to 60 seconds;
- behavior telemetry logging is separately throttled to 30 seconds.

## UI
- replaced the native QMessageBox ransomware warning with a calm, integrated
  BC Sentinel modal;
- the dialog shows only actual heuristic evidence;
- process attribution is explicitly shown as unavailable when it is unknown;
- no process is terminated automatically by this v0.1.x heuristic.

Detection logic for static files, EICAR, quarantine and history is unchanged.
