"""Deprecated v0.5 entry point kept for packaging compatibility."""
from sentinel.protection_service_windows import (
    BCSentinelProtectionService as BCSentinelTelemetryService,
    main,
)

if __name__ == "__main__":
    main()
