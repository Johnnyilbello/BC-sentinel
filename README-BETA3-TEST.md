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

Il launcher esegue la suite completa, upgrade/repair e tutti i gate live, quindi crea un task temporaneo della sessione interattiva con `RunLevel Limited` per il vero standard-user -> UAC. L'helper fallisce chiuso se resta elevato e il task viene eliminato automaticamente.

## Unico gate escluso
Il reboot è deliberatamente rinviato alla chiusura finale della roadmap. Nessun launcher Beta3 deve marcarlo PASS.

## FIX1 — admin standard-user UAC launcher
Su alcune build di Windows 11 `Shell.Application` può ereditare il token elevato. FIX1 usa invece il token filtrato dell'Explorer della sessione corrente; il child deve confermare `is_admin=false` prima di poter eseguire la broker acceptance.

Dopo aver già completato la suite Beta3, per verificare soltanto questa correzione da PowerShell amministratore:

```powershell
.\RETEST-V010-BETA3-STANDARD-UAC-ADMIN.bat
```

Il launcher completo `TEST-V010-BETA3-ALL-ADMIN.bat` usa automaticamente lo stesso percorso corretto.

## FIX2 harness UAC
Il launcher ADMIN non usa più `CreateProcessWithTokenW`: Windows Task Scheduler crea il processo della sessione interattiva con `RunLevel Limited`. Il retest mirato ora prepara automaticamente `.venv` se assente.
