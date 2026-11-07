# Verifiche del pacchetto BC Sentinel

## Pacchetto corrente

Il file singolo BC Sentinel Sperimentale.exe include il codice applicativo del commit a8e03c7. La sua impronta SHA-256 è b643b5e71cdadf5061b6cb41685b00387e0bf76eb2eb75855498271a575e3520. Il commit successivo d561e8b aggiunge una prova di annullamento senza modificare il codice applicativo.

| Verifica | Evidenza |
| --- | --- |
| Suite completa al commit fc13eba | 2.255 test passati senza warning |
| ZIP accodato a un contenitore MZ, al commit a8e03c7 | Nove test mirati passati, incluso il nuovo contenitore |
| Annullamento durante la visita ZIP, al commit d561e8b | Dieci test mirati passati |
| Eseguibile al commit a8e03c7 | Sei profili superati per autocontrollo, diagnostica e smoke UI |
| Portabilità | Avvio verificato da una cartella contenente il solo eseguibile |
| Storage Analyzer incluso | Apertura della finestra nativa superata |
| Interfaccia nativa al commit 8c8eeb5 | Nessuno scorrimento orizzontale nelle cinque pagine principali a 760, 960 e 1.440 pixel |
| Interfaccia nativa con percorso lungo | Sette pagine a 720 × 600 senza scorrimento orizzontale |
| Monitor e file bloccati | Recupero verificato con un handle Windows esclusivo rilasciato prima del secondo tentativo. Il blocco persistente produce un file saltato con errore |
| Moduli del pacchetto al commit 8c8eeb5 | Inventario verificato con scanner BC, monitor, quarantena e Storage Analyzer. Moduli di integrazione Defender assenti |

Le prove di avvio sono automatiche e locali. La verifica su una macchina pulita resta aperta. Il pacchetto è senza firma digitale. La suite completa precede l'ultima modifica applicativa agli ZIP, coperta dai test mirati indicati. La corrispondenza visiva al mockup richiede ancora una revisione finale di tutte le schermate e degli stati.

Il confronto con Defender è ancora da eseguire su un corpus autorizzato in un laboratorio con snapshot. Il classificatore Win64 valutato separatamente resta fuori dal pacchetto. [Valutazione Win64](EMBER-WIN64-VALUTAZIONE.md) · [Procedura del confronto](OFFLINE-CANDIDATE.md)

## Resoconto storico del 5 novembre 2026

Le sezioni seguenti descrivono il checkpoint a19b896. L'integrazione Defender riportata in questo checkpoint è stata rimossa dalle versioni correnti.


Verifiche eseguite su Windows il 5 novembre 2026, con Python 3.12.10, PySide6 6.11.2 e .NET Framework 4.8.
Il codice compilato del pacchetto corrisponde al commit a19b896fcab18de0cc2bb2dd4b1bf6cc5afa69a1. Gli aggiornamenti successivi a questa verifica riguardano le istruzioni e questo resoconto.

| Verifica | Risultato |
| --- | --- |
| Suite del codice attuale | 2.215 test passati, 42 warning |
| Nuovi controlli Storage e Defender, ripetuti dopo il controllo visivo | 13 test passati |
| Tre moduli storici Beta1 in ambiente ricostruito | 19 test passati |
| Sei moduli storici v0.9/v0.10 al commit 7d90b682 | 53 test passati |
| Tre moduli storici Beta2 al commit b943f1ee | 33 test passati |
| Storage Analyzer nativo | Totali, ordinamento, percorsi lunghi, collegamenti, annullamento, applicazioni, RAM, CSV e lettura dei comandi di disinstallazione verificati |
| Rimozioni native | File campione trovato nel Cestino e cartella campione eliminata definitivamente |
| Pacchetto portabile | Compilazione, avvio congelato, smoke Qt e rifiuto dell’output offline sul volume esaminato superati |
| Integrità del componente | SHA-256 dell’eseguibile Storage nel pacchetto uguale a quello compilato |
| Avvio con profili applicativi anomali | Sei scenari superati, inclusi JSON danneggiato, dati non finiti e licenza non valida |
| Defender sul PC | Interrogazione di stato in sola lettura completata |

## Interfaccia

La valutazione ha seguito i componenti e i colori del desktop esistente. La nuova voce è stata collegata ai punti di avvio effettivi Beta11 e Beta13, conservando gli indici delle pagine precedenti.

I controlli Qt sono stati renderizzati fuori schermo alle larghezze di 1.440, 960 e 560 pixel. Navigazione, ritorno alla pagina dopo l’aggiornamento dello stato, etichette accessibili e assenza di scorrimento orizzontale sono stati verificati automaticamente.

La revisione visiva ha corretto il contrasto del nuovo dialogo Defender. Il detector per markup ha restituito zero risultati sui target Python, ma non fornisce copertura tecnica dei widget Qt. La prova visiva deriva dai rendering dei controlli reali e dai test, senza automatizzare l’antivirus installato.

## Miglioramenti verificati

- Attivazione del controllo idle-backoff prima dell’avvio delle catture ETW.
- Eliminazione della raccolta globale forzata della memoria a ogni file nel parser PE basato su una copia di byte.
- Verifica di 512 mutazioni riproducibili dei metadati PE e regressione contro la raccolta globale per file.
- Comandi Defender limitati ad azioni predefinite, verifica della modalità del motore e conferma esplicita della rimozione.
- Componente Storage incluso nelle procedure di compilazione e test Windows automatici.

## Limiti della prova

Le scansioni e rimozioni Defender sono state simulate nei test automatici. Sul PC è stata eseguita l’interrogazione di stato. Le prove native di eliminazione hanno riguardato esclusivamente dati campione.

Il test dell’interfaccia Sentinel è un rendering Qt con test automatici, distinto da una sessione manuale completa del pacchetto. Il pacchetto non è firmato. Questa prova locale non costituisce una verifica su macchina pulita, una certificazione antimalware o una garanzia contro tutte le minacce.

Gli esiti dei test storici appartengono ai rispettivi checkpoint o all’ambiente ricostruito indicato. La suite corrente continua a tenerli distinti.
