# BC Sentinel v0.10.0-beta.3 — test rapido

## Un solo comando da PowerShell normale

```powershell
.\TEST-V010-BETA3-ALL-NORMAL.bat
```

Il launcher esegue automaticamente la suite completa, le acceptance Beta1/Beta2/Beta3, compileall, apre una singola elevazione UAC per la fase amministratore, costruisce il Protection Service/Broker, esegue upgrade e repair reali, le acceptance service-live, Windows acceptance/benchmark e infine torna al processo standard per il vero gate standard-user -> UAC.

## Un solo comando da PowerShell amministratore

```powershell
.\TEST-V010-BETA3-ALL-ADMIN.bat
```

Il launcher esegue la suite completa, upgrade/repair e tutti i gate live, quindi tenta di avviare tramite Explorer un helper a integrità media per il vero standard-user -> UAC. L'helper fallisce chiuso se resta elevato.

## Unico gate escluso
Il reboot è deliberatamente rinviato alla chiusura finale della roadmap. Nessun launcher Beta3 deve marcarlo PASS.
