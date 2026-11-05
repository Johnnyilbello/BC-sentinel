# Verifica dell’integrazione Storage Analyzer e protezione Windows

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
