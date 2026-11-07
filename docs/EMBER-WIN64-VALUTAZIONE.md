# Valutazione del modello EMBER2024 Win64

La prova usa caratteristiche ed etichette del dataset EMBER2024 per misurare un possibile rilevatore di eseguibili Win64. Il modello resta fuori da BC Sentinel. La prova non misura il motore completo, l'estrazione da eseguibili reali o la protezione in tempo reale. [Dataset EMBER2024](https://huggingface.co/datasets/joyce8/EMBER2024)

La settimana dal 22 al 28 settembre 2024 serve a scegliere la soglia. Si parte da 0,99 e, se necessario, la si alza per contenere i falsi positivi entro lo 0,1% della calibrazione. Il modello ha mantenuto la soglia di 0,99. La settimana dall'8 al 14 dicembre è stata valutata dopo aver fissato la soglia.

| Gruppo Win64 | Minacce rilevate | Falsi positivi |
| --- | --- | --- |
| Calibrazione di settembre | 4.473 / 5.000 (89,46%) | 2 / 5.000 (0,04%) |
| Verifica di dicembre | 4.408 / 5.000 (88,16%) | 3 / 5.000 (0,06%) |
| Campioni evasivi del challenge | 69 / 814 (8,48%) | Nessun benigno nel gruppo |

Ogni settimana contiene 10.000 righe duplicate per SHA-256, escluse dai conteggi. Le due settimane non hanno SHA-256 in comune. Il catalogo ESET integrato in BC non ha dato corrispondenze esatte su questi gruppi. La prova non comprende le regole YARA, gli altri rilevatori BC o una scansione Defender degli stessi file. La sensibilità dell'8,48% sul challenge lascia irrisolta la copertura dei campioni evasivi.

## Ripetere la prova

Usare un ambiente Python 3.12 dedicato con NumPy 2.5.4, scikit-learn 1.9.1, LightGBM 4.7.0, Signify 0.7.1 e `thrember` dal commit indicato. Le versioni di Signify più recenti hanno cambiato l'interfaccia usata dall'estrattore. [Revisione dell'estrattore](https://github.com/FutureComputing4AI/EMBER2024/tree/0ef753e81d98bf209f71b03cd331dfc190b5b54d)

In una cartella dati salvare `EMBER2024_Win64.model` come `EMBER2024_Win64-e5b945dd.model` e `challenge.zip` come `EMBER2024-challenge-3d23ef.zip`. Scaricare da `Win64_test.zip` solo i seguenti intervalli inclusivi tramite la richiesta HTTP Range. Verificare il codice 206 e che il campo Content-Range riporti l'intervallo richiesto su 1.176.459.716 byte. [Revisione del modello](https://huggingface.co/joyce8/EMBER2024-benchmark-models/tree/e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2) · [Revisione del dataset](https://huggingface.co/datasets/joyce8/EMBER2024/tree/3d23efef7c0f0b702c5024400cfff4c3744a3832)

| File locale | Intervallo di byte |
| --- | --- |
| `ember-win64-first.bin` | `0-104108840` |
| `ember-win64-last.bin` | `1076659619-1176458685` |
| `ember-win64-tail.bin` | `1176394180-1176459715` |

```powershell
python tools/evaluate_ember_win64.py "C:\percorso\dati"
```

Lo script verifica le impronte SHA-256 di tutti gli input, le CRC dei due membri ZIP e la compatibilità tra modello ed estrattore. Stampa i conteggi e le esclusioni in JSON. Legge esclusivamente i dati pubblicati per la prova, senza eseguire campioni.
