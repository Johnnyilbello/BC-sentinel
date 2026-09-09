# BC Sentinel v0.2.1-beta FIX2

Fixes the remaining startup failure in v0.2.1.

Root cause:
the newly inserted privileged telemetry methods and Activity-page methods were
at module scope instead of inside `MainWindow`. This also caused later UI
methods (Quarantine, History, Protection, Settings and related logic) to become
nested under the wrong functions and therefore unavailable at runtime.

Fixes:
- restore telemetry-service methods as real `MainWindow` members;
- restore Activity as a real `MainWindow` page;
- restore Quarantine, History, Protection and Settings methods;
- add AST regression tests for class ownership of critical UI methods;
- replace PowerShell native stderr piping with `Start-Process` file redirection,
  so Windows PowerShell 5.1 can show full Python tracebacks without terminating
  on the first stderr line.

Detection, scoring, quarantine and ransomware policies were not weakened.
