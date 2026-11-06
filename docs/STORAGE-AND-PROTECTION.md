# Storage Analyzer e controlli di protezione

## Spazio su disco e RAM

Nel desktop apri **Storage Analyzer → Apri BC Storage Analyzer**.
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

## Scansionare e rimuovere minacce con Defender

Apri **Scansione** per i controlli Defender. La Dashboard legge lo stato all’avvio e offre anche i comandi di scansione rapida e completa. **Scansiona una cartella** permette di scegliere il percorso.
Il pannello riporta modalità del motore, versione e data delle firme e minacce attive.
Le scansioni si abilitano quando Defender dichiara servizio e antivirus attivi in modalità normale.

Defender applica le impostazioni di risposta del PC durante le scansioni, che possono includere quarantena e rimozione.
**Rimuovi tutte le minacce attive rilevate da Defender** richiede conferma e agisce su tutte le minacce attive del motore Microsoft. Errori e permessi insufficienti vengono mostrati nel pannello.

La disponibilità dipende dalla configurazione Windows. Possono servire permessi amministrativi. La finestra richiede di attendere la conclusione del comando prima di chiudersi.

In **Protezione** puoi aggiornare le firme, aprire Sicurezza di Windows o avviare Sentinel come amministratore. In **Quarantena** puoi aggiornare i rilevamenti e aprire la gestione degli elementi isolati in Sicurezza di Windows. **Cronologia** registra le operazioni del desktop e consente di esportarle.

[Riferimento dei comandi Defender](https://learn.microsoft.com/en-us/powershell/module/defender/), [rimozione delle minacce attive](https://learn.microsoft.com/en-us/powershell/module/defender/remove-mpthreat)

## Compilazione e integrazione

Il desktop Beta13 e il punto di avvio Beta11 includono Storage Analyzer.
I costruttori dei checkpoint storici mantengono un’opzione esplicita per riprodurre le interfacce precedenti nei test.

tools/BUILD-STORAGE-ANALYZER.ps1 compila i quattro sorgenti C# con il compilatore .NET Framework di Windows.
Le procedure Beta11, installer Beta13 e candidato offline includono il risultato nelle risorse PyInstaller.
Il componente viene risolto da una posizione controllata nel progetto o nel pacchetto.
La versione a file singolo estrae automaticamente i componenti temporanei. Chiudi Storage Analyzer prima di chiudere Sentinel, così i componenti restano disponibili per tutta la sessione. Il pulsante impedisce aperture duplicate dalla stessa finestra finché il processo è attivo.

## Verifiche e limiti

I test verificano disponibilità, errori di avvio, navigazione, finestre ridotte, riapertura e conferma negata della rimozione Defender.
Scansioni e rimozioni Defender vengono simulate nei test automatici.
I test nativi di Storage Analyzer provano realmente Cestino ed eliminazione definitiva su campioni creati appositamente.

La nuova pagina usa il motore Microsoft. Le classificazioni autonome di Sentinel restano limitate ai rilevatori e ai casi provati. Una scansione conclusa non garantisce che il PC sia libero da tutte le minacce.
