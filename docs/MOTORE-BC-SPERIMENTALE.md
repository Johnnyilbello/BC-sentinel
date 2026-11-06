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

Usare soltanto cataloghi verificati: un hash nel catalogo produce una corrispondenza, non una prova indipendente di pericolosità. La scansione può essere annullata; collegamenti, file oltre 64 MiB e errori di accesso sono conteggiati come elementi saltati. Non elimina, isola o modifica i file. Non analizza archivi, memoria o comportamenti, e non offre monitoraggio in tempo reale. Un esito senza corrispondenze non garantisce la sicurezza del PC.

Le pagine **Scansione**, **Protezione** e **Quarantena** operano su Microsoft Defender tramite le API di Windows. Il componente BC e Defender sono distinti. Lo scanner offline BC è separato e può utilizzare anche regole YARA. Nessun confronto indipendente dimostra che il componente BC superi Defender o altri antivirus. Mantenere attiva una protezione antivirus affidabile.

Avvio: aprire il file `BC Sentinel Sperimentale.exe`, selezionare **Motore BC**, facoltativamente caricare un catalogo e scegliere la cartella. Per analizzare spazio e RAM aprire **Storage Analyzer**. I percorsi inaccessibili possono richiedere permessi superiori; non elevare il programma senza necessità.
