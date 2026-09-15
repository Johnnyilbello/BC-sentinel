# Product polish UI dopo B6-5.9

Base immutata: `checkpoint/v011-beta6-b659-pass`, commit
`72c18bbdf1c50c633343750ead0f2467d8705e12`.
Branch: `feature/v011-beta6-post-b659-ui-polish`.

## Modifiche

- Quarantena vuota: copy coerente con il provider già presente.
- Scansione rapida: rimossi riferimenti roadmap anche da tooltip e nomi accessibili.
- Traduzione solo nella presentazione: motivazioni scanner, categorie e sorgenti;
  fallback italiano per codici sconosciuti. Modelli, severità, confidenza, percorsi
  e prove non vengono modificati. La scheda conserva i valori originali nei Dettagli avanzati.
- Refresh Quarantena ricollegato al refresh completo, per ricreare i pulsanti
  di ripristino delle sole righe autorizzate. Le righe degradate non ricevono pulsanti.
- Filtri privi di implementazione mantenuti disabilitati anche dopo il caricamento
  di dati; tooltip espliciti. Il dialogo legacy ora apre realmente i dettagli.

## Audit completo delle superfici richieste

| Superficie / controllo | Handler o comportamento | Verifica |
|---|---|---|
| Navigazione delle sei pagine | `_navigate`, selezione pagina; nessuna scansione | Click Qt su ogni voce e controllo pagina attiva |
| Dashboard: scansione rapida, sidebar | `_start_smart_scan`, stesso coordinatore | Click con provider fixture, un solo avvio |
| Dashboard: aggiorna stato | `_refresh_snapshot`, lettura passiva | Click; nessun avvio scanner |
| Dashboard: dettagli protezioni | Toggle dettagli | Click apri/chiudi |
| Dashboard / Protezione: Apri Recovery | Handler esistente, solo apertura esplicita | Click con destinazione mock, nessuna azione reale |
| Dashboard / Scansione: completa | Intenzionalmente disabilitata, contratto assente | Stato disabilitato verificato |
| Scansione: rapida / annulla | Callback coordinatore; cancellazione cooperativa | Click Qt, provider fixture e annullamento osservato |
| Scansione: dettagli scan, card, risoluzione | Toggle dei pannelli di prova | Click e visibilità verificati |
| Scansione: quarantena / ripristino | Controller accettato e conferma esplicita | Dialoghi reali, click conferma/annulla, esecuzione mock |
| Scansione: azione non ammissibile | Disabilitata dal controller | Nessuna nuova autorità |
| Quarantena: aggiorna lista | `_refresh_quarantine_rows` | Due click, pulsante restore ricreato |
| Quarantena: Ripristina file | Conferma e `rollback` accettati | Click + No; mock rollback mai chiamato |
| Quarantena: stato degradato | Nessun pulsante restore | Riga fixture verificata |
| Quarantena: In quarantena | Indicatore della vista corrente, disabilitato | Nessun falso tab operativo |
| Quarantena: Ripristinati / Filtri | Intenzionalmente disabilitati | Nessuna implementazione disponibile |
| Cronologia: Tutti / filtri livello | Vista corrente / filtri non disponibili, disabilitati | Verifica anche con righe presenti |
| Tabelle Quarantena / Cronologia | Selezione righe nativa Qt, nessuna modifica | Click cella; editing disabilitato |
| Protezione / Impostazioni: indicatori | Widget di sola lettura, nessun comando servizio | Click indicatori Impostazioni non cambia stato |
| Supporto / Account | Voci già disabilitate, nessuna pagina collegata | Stato e tooltip espliciti; nomi accessibili anche compatti |
| Scroll, selezione testo, ridimensionamento | Controlli nativi Qt, nessun dispatch sicurezza | Layout desktop/compatto e regressioni precedenti |
| Dialogo legacy: Dettagli / Ignora / Quarantena | Toggle / reject / callback solo se fornita | Click dettagli e chiusura; quarantena assente disabilitata |

Il test enumera inoltre tutti i pulsanti visibili nelle sei pagine e richiede
un ricevitore clicked/toggled per ogni pulsante abilitato, un nome e un tooltip.
Supporto e Account restano indisponibili: non vengono inventati servizi o pagine.

## Invarianti

Nessun file engine, controller, gate, provider o policy di remediation modificato.
DELETE, REPAIR e cleanup automatico rimangono chiusi. Quarantena e ripristino
mantengono esclusivamente le autorizzazioni manuali già accettate; niente automatismi.
Nessun checkpoint creato, spostato o aggiornato.

## Acceptance

`TEST-POST-B659-UI.ps1 -OpenUI` esegue test deterministici e click Qt offscreen,
regressioni B6-5.8/B6-5.9, scansione UI e qualità UI, quindi self-check.
Solo dopo PASS apre la UI normale con il preflight runtime storico e SHA-256
già accettati. XML JUnit: `acceptance-post-b659-ui.xml`.

Il launcher usa un percorso temporaneo univoco esterno al repository, necessario
per rispettare le esclusioni del controller. `-Python` e `-TestRoot` consentono
runtime e directory di test espliciti. Conserva le fixture per diagnosi.
Per l'apertura UI servono PySide6 e il runtime storico Consolidation_FULL locale.

CI Windows dedicata in `.github/workflows/post-b659-ui.yml`, con XML allegato
anche in caso di errore. L'apertura interattiva sul dispositivo resta un passo
locale: Qt offscreen non certifica il rendering del desktop dell'utente.
