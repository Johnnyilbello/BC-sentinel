# BC Sentinel v0.10.0-rc.1 — test completo

## PowerShell normale — un solo comando

```powershell
.\TEST-V010-RC1-ALL-NORMAL.bat
```

Esegue automaticamente full regression, Beta1/Beta2/Beta3/RC1 acceptance, compileall, elevazione della fase nativa, build, upgrade, repair, service-live, benchmark e infine il vero standard-user -> UAC dal processo originale non elevato.

## PowerShell amministratore — un solo comando

```powershell
.\TEST-V010-RC1-ALL-ADMIN.bat
```

Esegue automaticamente la stessa copertura completa e crea il processo standard-user tramite task temporaneo `Interactive + RunLevel Limited`; il child deve verificare `is_admin=false` prima che il gate UAC possa passare.

## Gate escluso
Solo il reboot è rinviato alla chiusura finale della roadmap.

## Regola permanente dei launcher
Upgrade, repair e standard-user -> UAC non devono essere rimossi dai master launcher delle versioni successive.
