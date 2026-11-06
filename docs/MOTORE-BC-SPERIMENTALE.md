# Motore BC sperimentale

La pagina **Motore BC** esegue una scansione locale su richiesta, indipendente da Microsoft Defender. Calcola lo SHA-256 dei file e confronta gli hash con un catalogo scelto dall'utente. Il catalogo integrato contiene esclusivamente l'hash del file EICAR standard di 68 byte: è un test innocuo, non un database di malware. Le varianti EICAR con spazi o a capo non corrispondono a questo hash. Nessun aggiornamento automatico delle firme è incluso.

Il pulsante **Carica catalogo hash** accetta il formato JSON già usato dallo scanner offline:

```json
{
  "schema": "bc-sentinel-offline-intel-v1",
  "approved": true,
  "sha256": [
    {"value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "name": "esempio", "source": "catalogo locale"}
  ]
}
```

Si possono caricare regole YARA locali usando **Carica regole YARA**. Le regole vengono compilate senza include, ogni analisi ha un limite di tempo e gli errori vengono segnalati. Le regole sono fornite dall'utente: non è incluso un set di regole malware né un servizio di aggiornamento. Usare soltanto cataloghi e regole verificati: una corrispondenza non è una prova indipendente di pericolosità. La scansione può essere annullata; collegamenti, file oltre 64 MiB e errori di accesso sono conteggiati come elementi saltati. Non elimina, isola o modifica i file. Non analizza memoria o comportamenti, e non offre monitoraggio in tempo reale. Un esito senza corrispondenze non garantisce la sicurezza del PC.

La scansione BC controlla anche il primo livello di ZIP, JAR e documenti Office basati su ZIP. I membri vengono letti in memoria e confrontati con gli stessi hash e regole. La scansione ammette fino a 256 membri, 16 MiB per membro e 64 MiB di espansione complessiva, con metodi Store e Deflate. I contenitori annidati vengono analizzati come file e la mancata apertura dei loro membri è segnalata come copertura parziale.

In **Scansione → Monitoraggio cartella**, selezionare una cartella per analizzare i file nuovi, rinominati o modificati anche nelle sottocartelle. Si usano il catalogo e le regole selezionati all'avvio del monitor. Gli eventi ripetuti vengono accorpati e la coda applicativa contiene al massimo 1.024 percorsi. La schermata espone rilevamenti, errori e saturazione della coda. I file già presenti richiedono una scansione manuale. Il monitor analizza dopo la modifica, funziona solo mentre l'app è aperta e non blocca l'apertura o l'esecuzione dei file.

Il monitor segnala anche almeno 15 rinomine distinte di documenti, in 12 secondi, verso la stessa estensione esterna all'elenco dei tipi di documento osservati. L'avviso riporta la cartella, l'estensione e il conteggio. Può segnalare rinomine legittime in blocco e non attribuisce l'attività a un processo. **Minacce** mostra le corrispondenze e gli avvisi BC della sessione, in una sezione separata dai rilevamenti di Defender.

In **Minacce → Quarantena BC** puoi isolare un file dopo una corrispondenza esatta con il catalogo e una conferma. Il file deve essere in Desktop, Documenti o Download e occupare al massimo 16 MiB. Il motore ricontrolla l'hash su un handle esclusivo e verifica la copia cifrata con Windows DPAPI prima di rimuovere l'originale. Il deposito si riapre con lo stesso account Windows. Il ripristino verifica il contenuto e rifiuta un percorso già occupato. Conserva i byte del file, senza ricreare le proprietà originali come date e ACL. Il flusso rifiuta file con flussi NTFS aggiuntivi, collegamenti fisici multipli e percorsi non idonei. Le regole YARA, gli avvisi comportamentali e i membri di archivio non abilitano l'isolamento.

Le pagine **Microsoft Defender**, **Protezione** e **Minacce** operano su Microsoft Defender tramite le API di Windows. Il componente BC e Defender sono distinti. Lo scanner offline BC è separato e può utilizzare anche regole YARA. Nessun confronto indipendente dimostra che il componente BC superi Defender o altri antivirus. Mantenere attiva una protezione antivirus affidabile.

Avvio: aprire il file `BC Sentinel Sperimentale.exe`, selezionare **Scansione**, facoltativamente caricare un catalogo e scegliere la cartella. Per analizzare spazio e RAM aprire **Storage Analyzer**. I percorsi inaccessibili possono richiedere permessi superiori; non elevare il programma senza necessità.
