# BC Sentinel

BC Sentinel è un progetto Windows per analisi delle minacce, scansione offline, recupero e gestione dello spazio del PC. L’interfaccia è in italiano.

La versione in sviluppo integra **BC Storage Analyzer**, un **motore BC sperimentale** di confronto hash su richiesta e i controlli separati di **Microsoft Defender** per scansione e rimozione delle minacce attive rilevate. Il motore BC include soltanto l'hash EICAR e non offre protezione in tempo reale. Il progetto è in valutazione interna. I test non garantiscono il riconoscimento di ogni malware.

## Cosa puoi fare

| Area | Utilizzo |
| --- | --- |
| Dashboard | Leggere lo stato reale del motore Windows e avviare i controlli |
| Motore BC | Confrontare gli hash di una cartella con EICAR e un catalogo locale approvato; nessuna modifica ai file |
| Scansione offline | Esaminare Windows offline con SHA-256, YARA e controlli strutturali su PE e ZIP |
| Protezione → Microsoft Defender | Leggere lo stato del motore Windows, avviare scansioni e richiedere la rimozione delle minacce attive |
| Storage Analyzer | Confrontare unità, cartelle, file, estensioni, applicazioni e RAM per processo |
| Rimozioni in Storage Analyzer | Spostare nel Cestino, eliminare definitivamente o disinstallare un’app dopo conferma |
| Quarantena | Consultare i rilevamenti di Defender e aprire la gestione di Sicurezza di Windows |

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

Apri **Storage Analyzer** nel menu laterale per analizzare spazio e RAM. Le scansioni antivirus si avviano dalla **Dashboard** o da **Scansione**. La Dashboard legge automaticamente lo stato del motore. **Protezione** offre aggiornamento firme, accesso a Sicurezza di Windows e avvio come amministratore.

Defender applica le impostazioni di risposta configurate in Windows durante le scansioni. Il comando di rimozione riguarda tutte le minacce attive riconosciute da Defender. Permessi insufficienti, motore disabilitato o modalità passiva vengono riportati nell’interfaccia.

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
