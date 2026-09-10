# Source Sync — v0.11.0-beta.1

## Authoritative Windows baseline
The development source for v0.11 must be applied to the complete artifact:

`BC_Sentinel_v0_10_0_RC1_Web_Protection_Consolidation_FULL.zip`

That FULL artifact is the package associated with the successful v0.10 RC1 one-command Windows run.

## Connected GitHub state
The repository branch `v0.10.0-rc.1` contains the v0.10 development/consolidation delta but is smaller than the complete Windows artifact. Therefore:

- do not label a GitHub source ZIP as the FULL Windows release yet;
- do not delete files present only in the complete RC1 artifact;
- do not weaken or skip tests because the GitHub delta lacks a dependency;
- synchronize the complete tree before producing the v0.11 FULL Windows ZIP;
- retain the existing checkpoint/update/UAC/firewall/web/antispyware/antimalware hardening files unchanged unless a v0.11 change explicitly requires modification.

## v0.11 delta currently on GitHub
- `sentinel/edr.py`
- `sentinel/edr_adapter.py`
- `tools/v011_edr_acceptance.py`
- `tests/test_v011_beta1_edr_foundation.py`
- `tests/test_v011_beta1_edr_adapter.py`
- v0.11 one-command test orchestration;
- version/config metadata;
- release/test/roadmap documentation.

## Acceptance rule
GitHub synchronization is complete only when the full-tree package can execute:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

and reach:

```text
BC SENTINEL v0.11.0-beta.1 — ALL GATES PASS
```

without removing any existing regression/native gate. Reboot remains deferred to final-roadmap validation.
