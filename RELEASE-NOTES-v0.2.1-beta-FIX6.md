# BC Sentinel v0.2.1-beta FIX6

Fixes Windows build failure caused by the FIX5 taskbar-icon regression test
importing Pillow (`PIL`) even though Pillow is not a BC Sentinel dependency.

FIX6:
- removes Pillow from the test suite;
- parses the ICO directory with Python's standard-library `struct` module;
- preserves validation of all required Windows taskbar icon sizes;
- adds a regression test ensuring the automated suite remains Pillow-free.

No runtime antivirus dependency was added.
No ETW, scanner, scoring, ransomware, quarantine or telemetry behavior changed.
