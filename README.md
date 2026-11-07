# BC Sentinel

BC Sentinel è un progetto Windows per analisi delle minacce, scansione offline, recupero e gestione dello spazio del PC. L’interfaccia è in italiano.

La versione in sviluppo integra **BC Storage Analyzer** e un **motore BC sperimentale** con indicatori ESET Research, monitoraggio di una cartella e quarantena cifrata. Il monitor BC analizza i file dopo la modifica mentre l'applicazione è aperta. Il progetto è in valutazione interna.

## Cosa puoi fare

| Area | Utilizzo |
| --- | --- |
| Panoramica | Avviare la scansione BC e consultare risultati, attività recenti e spazio su disco |
| Scansione | Analizzare una cartella e i file modificati con SHA-256 e regole YARA |
| Minacce | Consultare gli avvisi BC, isolare e ripristinare file idonei |
| Archivio | Aprire Storage Analyzer per confrontare unità, cartelle, file, estensioni, applicazioni e RAM per processo |
| Impostazioni | Consultare la diagnostica e aprire lo scanner offline di Windows |

## Avvio su Windows

La versione a file singolo si avvia con un doppio clic su **BC Sentinel.exe**. Include l’interfaccia e Storage Analyzer. I componenti vengono estratti automaticamente in una cartella temporanea durante l’esecuzione.

Per compilare questa versione dai sorgenti, usa tools/BUILD-SINGLE-EXE.ps1 con -OutputDirectory seguito dalla cartella di destinazione e -PythonPath seguito dal percorso di python.exe.

Dai sorgenti servono Python 3.12 e le dipendenze di requirements.txt.

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
powershell.exe -NoProfile -File .\tools\BUILD-STORAGE-ANALYZER.ps1
$env:PYTHONPATH = (Get-Location).Path
.\.venv\Scripts\python.exe .\packaging\beta13_desktop_entry.py
~~~

Apri **Archivio → Apri BC Storage Analyzer** per analizzare spazio e RAM. Le scansioni BC si avviano da **Panoramica** o da **Scansione**. **Panoramica → Vedi tutto** apre la cronologia delle operazioni. **Impostazioni** include l'accesso alla scansione offline, alla diagnostica e all'avvio come amministratore.

## Guide e limiti

- [Storage Analyzer e controlli di protezione](docs/STORAGE-AND-PROTECTION.md)
- [Motore BC sperimentale: utilizzo e limiti](docs/MOTORE-BC-SPERIMENTALE.md)
- [Risultati delle verifiche dell’integrazione](docs/VALIDATION-STORAGE-PROTECTION.md)
- [Scansione offline e qualificazione](docs/OFFLINE-CANDIDATE.md)
- [Installazione Windows](docs/WINDOWS-INSTALLATION.md)
- [Canale stabile storico](STABLE-RELEASE.md)
- [Roadmap e checkpoint](ROADMAP.md)
- [Sicurezza e segnalazioni](SECURITY.md)

L’analisi offline è limitata ai percorsi, formati e budget documentati. Le euristiche producono anche elementi da esaminare manualmente. Lo spazio logico di Storage Analyzer può differire dall’occupazione fisica del volume.

## Test riproducibili

Usa una directory temporanea nuova. Alcuni test richiedono fixture nella cartella temporanea di Windows.

~~~powershell
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$testBase = Join-Path $env:TEMP ('BCSentinel-tests-' + [guid]::NewGuid().ToString('N'))
.\.venv\Scripts\python.exe -m pytest -q --basetemp $testBase
pwsh -NoProfile -File .\tools\TEST-STORAGE-ANALYZER.ps1
.\.venv\Scripts\python.exe .\tools\run_historical_beta1_tests.py
~~~

La prima suite verifica il codice attuale. Lo script PowerShell 7 prova Storage Analyzer su campioni dedicati, comprese le rimozioni. L’ultimo comando ricostruisce un ambiente isolato di compatibilità per tre moduli Beta1 archiviati. [Guida ai test storici](tests/historical/README.md)

## Struttura della repository

| Cartella | Contenuto |
| --- | --- |
| sentinel/ | Motori, modelli, controlli e interfaccia Python/Qt |
| tools/storage_analyzer/ | Sorgenti C# del componente portabile |
| packaging/ | Punti di avvio dei pacchetti Windows |
| tests/ | Test attuali e contratti storici separati |
| tools/ | Compilazione, verifiche e accettazione |
| docs/ | Guide e limiti delle verifiche |
| .github/workflows/ | Controlli automatici e costruzione dei pacchetti |

Per compilare il pacchetto completo da un commit salvato, usa BUILD-V014-OFFLINE-CANDIDATE.ps1 con -OutputRoot seguito da una nuova cartella esterna e -PythonPath seguito dal percorso di python.exe. La procedura registra commit e impronte dei file. La qualificazione su Windows pulito richiede le evidenze della guida offline.
