from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time

from sentinel.core.events import SecurityEvent
from sentinel.correlation_engine import BehavioralCorrelationEngine
from sentinel.database import Database
from sentinel.network_intelligence import NetworkReputationEngine


def public_ip(index: int) -> str:
    blocks=("8.8.8","1.1.1","9.9.9","4.2.2")
    prefix=blocks[(index//250) % len(blocks)]
    return f"{prefix}.{(index % 250)+1}"


def run(events: int, unique_endpoints: int, processes: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-v040-") as td:
        db=Database(Path(td)/"bench.sqlite")
        intelligence=NetworkReputationEngine(db)
        correlation=BehavioralCorrelationEngine(window_seconds=20,max_events_per_pid=120)

        # Seed local reputation states without any Internet access.
        db.upsert_endpoint_reputation(indicator=public_ip(0),kind="ip",status="malicious",source="benchmark",confidence=.99)
        db.upsert_endpoint_reputation(indicator=public_ip(1),kind="ip",status="suspicious",source="benchmark",confidence=.8)
        db.upsert_endpoint_reputation(indicator=public_ip(2),kind="ip",status="trusted",source="benchmark",confidence=.95)

        started=time.perf_counter()
        batches=[]
        correlations=[]
        scores=[]
        for i in range(events):
            endpoint=public_ip(i % unique_endpoints)
            pid=(i % processes)+100
            process="powershell.exe" if i % 200 == 0 else ("chrome.exe" if i % 3 == 0 else "sample.exe")
            path=(r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if process=="powershell.exe" else rf"C:\\Bench\\{process}")
            event=SecurityEvent(
                category="network",action="connect",source="benchmark",pid=pid,
                process_name=process,process_path=path,path=f"{endpoint}:443",
                data={"remote_addr":endpoint,"remote_port":443,"protocol":"TCP","state":"ESTABLISHED"},
            )
            rep=intelligence.assess_event(event)
            event.score=rep.score_delta
            event.reasons=rep.reasons
            event.data.update({
                "endpoint_status":rep.status,"endpoint_confidence":rep.confidence,
                "endpoint_first_seen":rep.first_seen,"endpoint_class":rep.address_class,
            })
            corr=correlation.assess(event,[])
            if corr.reasons:
                event.data["correlation_score_delta"]=corr.score_delta
                correlations.append({
                    "category":"behavioral_correlation","source_event_category":"network",
                    "source_event_action":"connect","pid":pid,"process_name":process,
                    "score_delta":corr.score_delta,"confidence":corr.confidence,"chain":"",
                    "reasons":corr.reasons,"data":{"path":event.path},
                })
            batches.append(event)
            scores.append(min(100,event.score+corr.score_delta))
            if len(batches)>=200:
                db.record_telemetry_batch(batches,correlations)
                batches.clear(); correlations.clear()
        if batches or correlations:
            db.record_telemetry_batch(batches,correlations)
        elapsed=time.perf_counter()-started

        observed=db.execute("SELECT COUNT(*) c FROM network_endpoint_observations")[0]["c"]
        stored=db.execute("SELECT COUNT(*) c FROM network_events")[0]["c"]
        return {
            "events":events,
            "unique_endpoints_requested":unique_endpoints,
            "processes":processes,
            "elapsed_seconds":round(elapsed,6),
            "events_per_second":round(events/elapsed,2) if elapsed else 0,
            "network_events_persisted":int(stored),
            "endpoint_process_pairs":int(observed),
            "max_correlated_score":max(scores) if scores else 0,
            "privacy":"synthetic/local-only; no external network lookup",
        }


def main():
    parser=argparse.ArgumentParser(description="BC Sentinel v0.4 local network-intelligence benchmark")
    parser.add_argument("--events",type=int,default=5000)
    parser.add_argument("--unique-endpoints",type=int,default=250)
    parser.add_argument("--processes",type=int,default=25)
    parser.add_argument("--output",default="benchmark_v040_network.json")
    args=parser.parse_args()
    result=run(max(1,args.events),max(1,args.unique_endpoints),max(1,args.processes))
    Path(args.output).write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
