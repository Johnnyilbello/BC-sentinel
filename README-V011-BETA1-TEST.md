# BC Sentinel v0.11.0-beta.1 — Test rapido

## Unico comando consigliato
Apri una **PowerShell normale** nella cartella FULL e lancia:

```powershell
.\UPDATE-TEST-V011-BETA1.bat
```

Questo è il comando permanente: scarica automaticamente l'ultimo delta del branch `v0.11.0-beta.1`, lo sovrappone alla baseline FULL senza cancellare i file presenti solo nel pacchetto completo e poi avvia tutti i gate.

Non aprire manualmente una seconda PowerShell amministrativa.

## Test senza aggiornamento Git
Se vuoi testare esattamente i file già presenti nella cartella, senza sincronizzare prima il branch:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

## Cosa fa automaticamente
1. verifica che la cartella sia una baseline FULL e non un delta GitHub incompleto;
2. con `UPDATE-TEST-V011-BETA1.bat` scarica e applica l'ultimo delta Git del branch;
3. crea `.venv` se manca;
4. installa/verifica le dipendenze;
5. applica le migration/compatibility v0.11, incluso il low-CPU runtime;
6. esegue tutta la suite pytest;
7. esegue EDR Beta1 acceptance;
8. riesegue le acceptances v0.10 RC1;
9. esegue compileall;
10. costruisce Protection Service e UAC Broker;
11. apre autonomamente la richiesta UAC;
12. nella fase elevata esegue targeted native + EDR tests;
13. installa il servizio se non esiste;
14. esegue upgrade reale oppure verifica il rifiuto same-version e passa al repair;
15. esegue repair reale;
16. riesegue le acceptances live v0.10;
17. esegue Windows acceptance e service hardening benchmark;
18. torna al contesto standard-user e verifica il percorso UAC Broker;
19. riesegue EDR acceptance post-admin;
20. stampa un unico esito finale.

## Low CPU final gate
Il runtime v0.11 installa esplicitamente il shim pywintrace prima dell'avvio delle sessioni ETW. I rientri anomali ripetuti di `ProcessTrace()` usano backoff adattivo e il consumer anonimo viene esposto nei diagnostici come `BCS-ETW-ProcessTrace` invece del generico `Thread-N`.

Le soglie rimangono invariate:

- idle CPU <= 25% di un core;
- IPC >= 10 richieste/s;
- benign storm <= 250% di un core.

## Esito atteso

```text
REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION
BC SENTINEL v0.11.0-beta.1 — ALL GATES PASS
```

Se la UAC viene annullata, il launcher deve terminare in FAIL: non è consentito saltare la fase amministrativa.

## Nota GitHub
Il branch di sviluppo resta un delta sulla baseline Windows FULL finché il tree completo della RC1 non viene sincronizzato. Il launcher di update non elimina file FULL-only e verifica la presenza della baseline prima di procedere.
