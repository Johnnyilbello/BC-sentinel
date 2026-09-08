# BC Sentinel v0.11.0-beta.1 — Test rapido

## Unico comando
Apri una **PowerShell normale** nella cartella FULL e lancia:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Non aprire manualmente una seconda PowerShell amministrativa.

## Cosa fa automaticamente
1. verifica che la cartella sia una baseline FULL e non un delta GitHub incompleto;
2. crea `.venv` se manca;
3. installa/verifica le dipendenze;
4. esegue tutta la suite pytest;
5. esegue EDR Beta1 acceptance;
6. riesegue le acceptances v0.10 RC1;
7. esegue compileall;
8. apre autonomamente la richiesta UAC;
9. nella fase elevata esegue targeted native + EDR tests;
10. costruisce Protection Service e UAC Broker;
11. installa il servizio se non esiste;
12. esegue upgrade reale oppure verifica il rifiuto same-version e passa al repair;
13. esegue repair reale;
14. riesegue le acceptances live v0.10;
15. esegue Windows acceptance e service hardening benchmark;
16. torna al contesto standard-user e verifica il percorso UAC Broker;
17. riesegue EDR acceptance post-admin;
18. stampa un unico esito finale.

## Esito atteso

```text
REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION
BC SENTINEL v0.11.0-beta.1 — ALL GATES PASS
```

Se la UAC viene annullata, il launcher deve terminare in FAIL: non è consentito saltare la fase amministrativa.

## Nota GitHub
Il branch di sviluppo non va trattato come pacchetto FULL finché il tree completo della RC1 Windows non è sincronizzato. Il launcher controlla esplicitamente questa condizione.
