# Motore BC sperimentale

La pagina **Scansione** esegue una scansione locale con il motore BC. Confronta gli SHA-256 con 6.138 indicatori pubblici di ESET Research e con il file di prova innocuo EICAR. Applica inoltre 12 sorgenti di regole YARA ESET ai contenuti che iniziano con l'intestazione DOS `MZ`. Le regole e gli indicatori provengono dalla revisione [825b826c5cbf](https://github.com/eset/malware-ioc/tree/825b826c5cbffcc1e59c16581ffdf7d527e8b695) e sono inclusi con la [licenza BSD](../sentinel/data/eset_ioc/LICENSE.txt). La scansione funziona offline.

Il generatore `python tools/build_eset_intel.py` legge da GitHub soltanto file di testo con hash, regole selezionate e licenza. Verifica l'identità Git dei file sorgente e compila le regole prima di scrivere il bundle. Per cambiare la revisione occorre anche aggiornare impronta e conteggio in `sentinel/bc_research_intel.py`. Il prodotto distribuito usa una revisione fissa, senza aggiornamento automatico.

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

Si possono aggiungere regole YARA locali usando **Carica regole YARA**. Le regole vengono compilate senza include, ogni analisi ha un limite di tempo e gli errori vengono segnalati. Usare soltanto cataloghi e regole verificati. Una corrispondenza è un indicatore da esaminare. La scansione può essere annullata e conteggia i collegamenti, i file oltre 64 MiB e gli errori di accesso tra gli elementi saltati. La scansione è in sola lettura. La risposta richiede una conferma dalla pagina Minacce.

La scansione BC controlla anche il primo livello di ZIP, JAR e documenti Office basati su ZIP. I membri vengono letti in memoria e confrontati con gli stessi hash e regole. La scansione ammette fino a 256 membri, 16 MiB per membro e 64 MiB di espansione complessiva, con metodi Store e Deflate. I contenitori annidati vengono analizzati come file e la mancata apertura dei loro membri è segnalata come copertura parziale.

Il detector statico cerca il passaggio di contenuto scaricato via HTTP o HTTPS a `Invoke-Expression` negli script PowerShell, anche attraverso una semplice assegnazione. Esamina inoltre `EncodedCommand` UTF-16LE negli avvii PowerShell da file batch e negli argomenti dei collegamenti Windows. Il limite è 256 KiB per file o membro e vengono esaminati fino a otto comandi codificati per blocco di argomenti. Gli script e i collegamenti non vengono avviati. L'analisi è lessicale, riconosce forme specifiche e non risolve il target del collegamento. Gli avvisi, visibili in **Minacce**, possono riguardare anche automazioni legittime e non abilitano la quarantena. [PowerShell EncodedCommand](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe) · [Formato Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af)

In **Scansione → Monitoraggio cartella**, selezionare una cartella per analizzare i file nuovi, rinominati o modificati anche nelle sottocartelle. Si usano il catalogo e le regole selezionati all'avvio del monitor. Gli eventi ripetuti vengono accorpati e la coda applicativa contiene al massimo 1.024 percorsi. La schermata espone rilevamenti, errori e saturazione della coda. I file già presenti richiedono una scansione manuale. Il monitor analizza dopo la modifica, funziona solo mentre l'app è aperta e non blocca l'apertura o l'esecuzione dei file.

Il monitor segnala anche almeno 15 rinomine distinte di documenti, in 12 secondi, verso la stessa estensione esterna all'elenco dei tipi di documento osservati. L'avviso riporta la cartella, l'estensione e il conteggio. Può segnalare rinomine legittime in blocco e non attribuisce l'attività a un processo. **Minacce** mostra le corrispondenze e gli avvisi BC della sessione, in una sezione separata dai rilevamenti di Defender.

In **Minacce → Quarantena BC** puoi isolare un file dopo una corrispondenza esatta con il catalogo e una conferma. Il file deve essere in Desktop, Documenti o Download e occupare al massimo 16 MiB. Il motore ricontrolla l'hash su un handle esclusivo e verifica la copia cifrata con Windows DPAPI prima di rimuovere l'originale. Il deposito si riapre con lo stesso account Windows. Il ripristino verifica il contenuto e rifiuta un percorso già occupato. Conserva i byte del file, senza ricreare le proprietà originali come date e ACL. Il flusso rifiuta file con flussi NTFS aggiuntivi, collegamenti fisici multipli e percorsi non idonei. Le regole YARA, gli avvisi comportamentali e i membri di archivio non abilitano l'isolamento.

Le pagine **Microsoft Defender**, **Protezione** e **Minacce** operano su Microsoft Defender tramite le API di Windows. Il componente BC e Defender sono distinti. Lo scanner offline BC è separato e può utilizzare anche regole YARA. Nessun confronto indipendente dimostra che il componente BC superi Defender o altri antivirus. Mantenere attiva una protezione antivirus affidabile.

Avvio: aprire il file `BC Sentinel Sperimentale.exe`, selezionare **Scansione**, facoltativamente caricare un catalogo e scegliere la cartella. Per analizzare spazio e RAM aprire **Storage Analyzer**. I percorsi inaccessibili possono richiedere permessi superiori; non elevare il programma senza necessità.
