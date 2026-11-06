# Analisi statica REA: limiti e osservazioni

Il componente osservato è `C:\Program Files\Windows Defender\MsMpEng.exe`, SHA-256 `c02655606c199ba276d2b01a796e6ebba07a41eede9c85fe516d9a5851290155`. REA 6.7.0 con Ghidra 12.1.4 lo ha importato in sola lettura, senza eseguire il programma. L'inventario (`ev_5f6981d953c841d724014651542000b3f4546d903122430aaf4cec9af238007f`) riporta 1.093 procedure e 494 stringhe definite da Ghidra; non garantisce di aver identificato tutte le procedure o stringhe.

La ricerca statica della parola `engine` (`ev_22cd5068ebf2af88f8094ac4111f9dff16329603d2ca83c8753d8f580c011b8f`) trova riferimenti testuali a configurazioni MpEngine e a EngineVersion. Queste stringhe non dimostrano come funzioni la rilevazione. Il file analizzato è soltanto un componente dell'installazione e non contiene necessariamente firme, modelli, servizi cloud o l'intero motore. Pseudocodice e simboli recuperati non equivalgono al sorgente originale.

Non è stata ottenuta una ricostruzione completa di Defender né una misura comparativa della capacità di rilevazione. Il motore BC è un'implementazione distinta, basata su hash e regole YARA selezionate dall'utente; le sue limitazioni sono descritte in [Motore BC sperimentale](MOTORE-BC-SPERIMENTALE.md).
