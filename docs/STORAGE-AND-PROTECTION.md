# Storage Analyzer e controlli di protezione

## Spazio su disco e RAM

Nel desktop apri **Archivio → Apri BC Storage Analyzer**.
Lo strumento usa una finestra dedicata. **Avvia scansione** analizza tutte le unità locali con lettera pronte all’uso oppure una singola unità.

Le schede mostrano dischi, cartelle, file, estensioni, stime delle applicazioni desktop e RAM residente per processo. Cartelle parte dal primo livello e permette di mostrare le sottocartelle. File e Cartelle mostrano fino a 500 voci ordinate per dimensione decrescente.

La scansione gestisce gli errori di accesso e permette di annullare conservando i risultati parziali. Salta i collegamenti alle cartelle. Le dimensioni logiche possono differire dall’occupazione fisica riportata da Windows.

Seleziona un percorso per aprirlo in Esplora file. **Esporta CSV** salva la scheda corrente con dimensioni in byte.

## Rimuovere file e applicazioni

Seleziona una voce in File o Cartelle e usa **Sposta nel Cestino** oppure **Elimina definitivamente**.
La conferma mostra il percorso e specifica quando riguarda una cartella con tutto il contenuto.
Le unità intere e alcuni percorsi critici sono protetti. Dopo un tentativo di rimozione, avvia una nuova scansione prima di effettuare altre rimozioni.

In Applicazioni, **Disinstalla applicazione** avvia la procedura registrata in Windows.
Se il comando manca o non è supportato, viene proposto di aprire App installate.
Le dimensioni delle applicazioni sono stime degli installer.

## Scansionare e isolare minacce con BC

Apri **Scansione** per scegliere una cartella o avviare il monitoraggio. **Minacce** raccoglie i rilevamenti e offre la quarantena cifrata e il ripristino dei file idonei. L'isolamento richiede conferma. [Motore BC sperimentale](MOTORE-BC-SPERIMENTALE.md)

**Impostazioni** include la scansione offline, la diagnostica e l'avvio come amministratore. **Panoramica → Vedi tutto** apre **Cronologia**, che consente di esportare le operazioni del desktop.

## Compilazione e integrazione

Il desktop Beta13 e il punto di avvio Beta11 includono Storage Analyzer.
I costruttori dei checkpoint storici mantengono un’opzione esplicita per riprodurre le interfacce precedenti nei test.

tools/BUILD-STORAGE-ANALYZER.ps1 compila i quattro sorgenti C# con il compilatore .NET Framework di Windows.
Le procedure Beta11, installer Beta13 e candidato offline includono il risultato nelle risorse PyInstaller.
Il componente viene risolto da una posizione controllata nel progetto o nel pacchetto.
La versione a file singolo estrae automaticamente i componenti temporanei. Chiudi Storage Analyzer prima di chiudere Sentinel, così i componenti restano disponibili per tutta la sessione. Il pulsante impedisce aperture duplicate dalla stessa finestra finché il processo è attivo.

## Verifiche e limiti

I test verificano navigazione, finestre ridotte, avvio e riapertura di Storage Analyzer, scansioni BC e quarantena su campioni dedicati.
I test nativi di Storage Analyzer provano realmente Cestino ed eliminazione definitiva su campioni creati appositamente.

Le classificazioni di Sentinel coprono i rilevatori e i casi documentati nella guida del motore BC.
