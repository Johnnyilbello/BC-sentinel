#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  COLLECT-V014-B1410-REAL-HOST-PREFLIGHT.sh \
    --analysis-interface <iface> \
    --management-interface <iface> \
    --vm <libvirt-vm-name> \
    --snapshot <snapshot-name> \
    --output <json-path>

Read-only collector. It does not modify networking, VM state, snapshots, or run
samples. Run it only on the dedicated Linux/KVM lab host.
EOF
}

ANALYSIS_IFACE=""
MANAGEMENT_IFACE=""
VM_NAME=""
SNAPSHOT_NAME=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --analysis-interface) ANALYSIS_IFACE="\${2:-}"; shift 2 ;;
    --management-interface) MANAGEMENT_IFACE="\${2:-}"; shift 2 ;;
    --vm) VM_NAME="\${2:-}"; shift 2 ;;
    --snapshot) SNAPSHOT_NAME="\${2:-}"; shift 2 ;;
    --output) OUTPUT="\${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for value in "$ANALYSIS_IFACE" "$MANAGEMENT_IFACE" "$VM_NAME" "$SNAPSHOT_NAME" "$OUTPUT"; do
  [[ -n "$value" ]] || { usage >&2; exit 2; }
done

safe_name='^[A-Za-z0-9._:-]+$'
[[ "$ANALYSIS_IFACE" =~ $safe_name ]] || { echo "Unsafe analysis interface name" >&2; exit 2; }
[[ "$MANAGEMENT_IFACE" =~ $safe_name ]] || { echo "Unsafe management interface name" >&2; exit 2; }
[[ "$VM_NAME" =~ $safe_name ]] || { echo "Unsafe VM name" >&2; exit 2; }
[[ "$SNAPSHOT_NAME" =~ $safe_name ]] || { echo "Unsafe snapshot name" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || { echo "python3 is required to emit JSON" >&2; exit 2; }

HOST_OS="UNKNOWN"
if [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; then HOST_OS="LINUX"; fi
ARCH="$(uname -m 2>/dev/null || true)"

KVM_PRESENT=false
[[ -e /dev/kvm ]] && KVM_PRESENT=true

KVM_ACCESS=false
[[ -r /dev/kvm && -w /dev/kvm ]] && KVM_ACCESS=true

VIRSH_PRESENT=false
command -v virsh >/dev/null 2>&1 && VIRSH_PRESENT=true

QEMU_PRESENT=false
if command -v qemu-system-x86_64 >/dev/null 2>&1 || command -v qemu-kvm >/dev/null 2>&1; then
  QEMU_PRESENT=true
fi

VIRT_VALIDATE_PRESENT=false
command -v virt-host-validate >/dev/null 2>&1 && VIRT_VALIDATE_PRESENT=true

VIRT_VALIDATE_PASSED=false
if [[ "$VIRT_VALIDATE_PRESENT" == true ]]; then
  validate_output="$(virt-host-validate qemu 2>&1 || true)"
  if ! grep -Eq ':[[:space:]]*FAIL([[:space:]]|$)' <<<"$validate_output"; then
    VIRT_VALIDATE_PASSED=true
  fi
fi

VM_PRESENT=false
SNAPSHOT_PRESENT=false
SHARED_FS=false
USB_HOSTDEV=false
if [[ "$VIRSH_PRESENT" == true ]] && virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  VM_PRESENT=true
  if virsh snapshot-list "$VM_NAME" --name 2>/dev/null | grep -Fxq "$SNAPSHOT_NAME"; then
    SNAPSHOT_PRESENT=true
  fi
  vm_xml="$(virsh dumpxml "$VM_NAME" 2>/dev/null || true)"
  if grep -Eq '<filesystem([[:space:]>])' <<<"$vm_xml"; then SHARED_FS=true; fi
  if grep -Eq '<hostdev[^>]*type=.usb.' <<<"$vm_xml"; then USB_HOSTDEV=true; fi
fi

ANALYSIS_IFACE_PRESENT=false
MANAGEMENT_IFACE_PRESENT=false
if command -v ip >/dev/null 2>&1; then
  ip link show dev "$ANALYSIS_IFACE" >/dev/null 2>&1 && ANALYSIS_IFACE_PRESENT=true
  ip link show dev "$MANAGEMENT_IFACE" >/dev/null 2>&1 && MANAGEMENT_IFACE_PRESENT=true
fi

INTERFACES_DISTINCT=false
[[ "$ANALYSIS_IFACE" != "$MANAGEMENT_IFACE" ]] && INTERFACES_DISTINCT=true

ANALYSIS_DEFAULT_ROUTE=false
if command -v ip >/dev/null 2>&1 && ip route show default dev "$ANALYSIS_IFACE" 2>/dev/null | grep -q .; then
  ANALYSIS_DEFAULT_ROUTE=true
fi

if [[ -r /etc/machine-id ]]; then
  fingerprint_source="$(cat /etc/machine-id)"
else
  fingerprint_source="$(hostname 2>/dev/null || printf 'unknown-host')"
fi
HOST_FINGERPRINT="$(printf '%s' "$fingerprint_source" | sha256sum | awk '{print $1}')"

export HOST_OS ARCH KVM_PRESENT KVM_ACCESS VIRSH_PRESENT QEMU_PRESENT
export VIRT_VALIDATE_PRESENT VIRT_VALIDATE_PASSED VM_PRESENT SNAPSHOT_PRESENT
export ANALYSIS_IFACE_PRESENT MANAGEMENT_IFACE_PRESENT INTERFACES_DISTINCT
export ANALYSIS_DEFAULT_ROUTE SHARED_FS USB_HOSTDEV HOST_FINGERPRINT OUTPUT

python3 - <<'PY'
import json
import os
from pathlib import Path

def b(name: str) -> bool:
    return os.environ[name].lower() == "true"

payload = {
    "schema": "bc-sentinel-beta14-real-host-preflight-v1",
    "evidence_class": "REAL_HOST_PREFLIGHT",
    "host_fingerprint_sha256": os.environ["HOST_FINGERPRINT"],
    "host_os": os.environ["HOST_OS"],
    "architecture": os.environ["ARCH"],
    "kvm_device_present": b("KVM_PRESENT"),
    "kvm_device_accessible": b("KVM_ACCESS"),
    "virsh_present": b("VIRSH_PRESENT"),
    "qemu_present": b("QEMU_PRESENT"),
    "virt_host_validate_present": b("VIRT_VALIDATE_PRESENT"),
    "virt_host_validate_passed": b("VIRT_VALIDATE_PASSED"),
    "analysis_vm_present": b("VM_PRESENT"),
    "snapshot_present": b("SNAPSHOT_PRESENT"),
    "analysis_interface_present": b("ANALYSIS_IFACE_PRESENT"),
    "management_interface_present": b("MANAGEMENT_IFACE_PRESENT"),
    "interfaces_distinct": b("INTERFACES_DISTINCT"),
    "analysis_interface_has_default_route": b("ANALYSIS_DEFAULT_ROUTE"),
    "shared_filesystem_device_present": b("SHARED_FS"),
    "usb_hostdev_present": b("USB_HOSTDEV"),
    "direct_internet_test_performed": False,
    "sample_execution_performed": False,
    "network_configuration_modified": False,
    "hypervisor_state_modified": False,
}
path = Path(os.environ["OUTPUT"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
print(json.dumps(payload, indent=2, sort_keys=True))
PY
