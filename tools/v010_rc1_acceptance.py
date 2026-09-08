from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.protection_client import ProtectionServiceClient
from sentinel.service_update import version_key
from sentinel.web_clone_scam import CLONE_SCAM_PROFILE, assess_page_context
from sentinel.web_deception import HEURISTIC_PROFILE, HEURISTIC_SCORE_CAP
from sentinel.web_response import WEB_RESPONSE_PROFILE

RC1_PROFILE = "v0.10.0-rc.1"

_CANONICAL = {
    "Microsoft": ["login.microsoftonline.com", "account.microsoft.com", "outlook.com", "office.com"],
    "Google": ["accounts.google.com", "mail.google.com", "www.google.com", "gstatic.com"],
    "GitHub": ["github.com", "objects.githubusercontent.com", "githubassets.com"],
    "PayPal": ["www.paypal.com", "paypal.com", "www.paypalobjects.com"],
    "Apple": ["apple.com", "idmsa.apple.com", "icloud.com"],
    "Amazon": ["amazon.com", "amazon.it", "s3.amazonaws.com"],
    "Cloudflare": ["cloudflare.com", "static.cloudflareinsights.com", "cdnjs.cloudflare.com"],
    "Salesforce": ["login.salesforce.com", "salesforce.com", "force.com"],
    "Atlassian": ["id.atlassian.com", "atlassian.com", "trello.com"],
}
_PATHS = ("/", "/login", "/account", "/assets/app.js", "/help", "/docs", "/oauth/authorize")


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(0.95 * (len(ordered) - 1)))))
    return ordered[index]


def _compatibility_matrix() -> dict:
    failures: list[dict] = []
    checked = 0
    for identity, hosts in _CANONICAL.items():
        for host in hosts:
            for path in _PATHS:
                checked += 1
                result = assess_page_context(
                    url=f"https://{host}{path}", declared_identity=identity,
                    page_title=f"{identity} account service",
                    visible_text="Sign in, support, billing and security information for your account.",
                    form_action=f"https://{host}/session",
                    form_fields=["email", "password"] if "login" in path or "account" in path else [],
                    payment_methods=["card"] if "billing" in path else [],
                )
                if result.score != 0 or result.status != "unknown" or result.block_recommended:
                    failures.append({"url": result.url, "identity": identity, "score": result.score, "status": result.status, "signals": result.signal_codes})
    for i in range(120):
        checked += 1
        host = f"service-{i}.corp.example"
        result = assess_page_context(
            url=f"https://{host}/portal/{i}", page_title="Customer portal",
            visible_text="Account login support invoice payment delivery security verification documentation.",
            form_action=f"https://{host}/submit", form_fields=["email"], payment_methods=["card"],
        )
        if result.score != 0 or result.status != "unknown" or result.block_recommended:
            failures.append({"url": result.url, "identity": "", "score": result.score, "status": result.status, "signals": result.signal_codes})
    return {"checked": checked, "failures": failures[:25], "failure_count": len(failures), "passed": len(failures) == 0}


def _local_latency() -> dict:
    samples_ms: list[float] = []
    loops = 1200
    start = time.perf_counter()
    for i in range(loops):
        t0 = time.perf_counter()
        assess_page_context(
            url=f"https://portal-{i % 97}.enterprise.example/account",
            page_title="Enterprise account portal",
            visible_text="Login support billing security documentation",
            form_action=f"https://portal-{i % 97}.enterprise.example/session", form_fields=["email"],
        )
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
    elapsed = time.perf_counter() - start
    throughput = loops / max(elapsed, 1e-9)
    p95 = _p95(samples_ms)
    return {
        "iterations": loops, "elapsed_seconds": round(elapsed, 6),
        "throughput_per_second": round(throughput, 2),
        "median_ms": round(statistics.median(samples_ms), 4), "p95_ms": round(p95, 4),
        "thresholds": {"min_throughput_per_second": 100.0, "max_p95_ms": 25.0},
        "passed": throughput >= 100.0 and p95 <= 25.0,
    }


def run(*, service_live: bool = False) -> dict:
    compatibility = _compatibility_matrix(); latency = _local_latency()
    clone = assess_page_context(url="https://microsoft-login.example/verify", declared_identity="Microsoft", page_title="Microsoft account verification", visible_text="Sign in to verify", form_action="https://collector.example/post", form_fields=["email", "password", "otp"])
    result = {
        "product":"BC Sentinel","version":APP_VERSION,"milestone":RC1_PROFILE,
        "profiles":{"beta1_deception":HEURISTIC_PROFILE,"beta2_response":WEB_RESPONSE_PROFILE,"beta3_clone_scam":CLONE_SCAM_PROFILE,"rc1_consolidation":RC1_PROFILE},
        "compatibility":compatibility,"performance":{"local_page_assessment":latency,"service_ipc":None},
        "safety":{"heuristic_score_cap":HEURISTIC_SCORE_CAP,"heuristic_only_below_high":HEURISTIC_SCORE_CAP<=49,"clone_detection_preserved":clone.status=="suspicious" and clone.block_recommended is False,"mitm_https":False,"heuristic_auto_block":False,"cloud_required":False,"reboot_gate_deferred":True},
        "service_live_requested":bool(service_live),"service":None,"local_passed":False,"service_live_passed":None,"passed":False,
    }
    result["local_passed"] = bool(version_key(APP_VERSION) >= version_key("0.10.0-rc.1") and compatibility["passed"] and latency["passed"] and result["safety"]["heuristic_only_below_high"] and result["safety"]["clone_detection_preserved"])
    if service_live:
        client = ProtectionServiceClient(timeout=3.0); status = client.request("web_status")
        latencies=[]; responses=[]
        for _ in range(25):
            t0=time.perf_counter(); response=client.request("web_clone_scam_assess", **{"url":"https://microsoft-login.example/verify","declared_identity":"Microsoft","page_title":"Microsoft verify","visible_text":"Sign in to verify","form_action":"https://collector.example/post","form_fields":["password"],"payment_methods":[],"link_hosts":[],"redirect_chain":[]}); latencies.append((time.perf_counter()-t0)*1000.0); responses.append(response or {})
        ipc={"requests":len(latencies),"median_ms":round(statistics.median(latencies),3),"p95_ms":round(_p95(latencies),3),"max_p95_ms":750.0,"all_ok":all(item.get("ok") for item in responses)}; ipc["passed"]=bool(ipc["all_ok"] and ipc["p95_ms"]<=ipc["max_p95_ms"]); result["performance"]["service_ipc"]=ipc
        web=(status or {}).get("web") or {}; final=(responses[-1].get("assessment") if responses else {}) or {}; result["service"]={"status":status,"assessment":final}
        result["service_live_passed"]=bool((status or {}).get("ok") and web.get("deception_profile")==HEURISTIC_PROFILE and web.get("response_profile")==WEB_RESPONSE_PROFILE and web.get("clone_scam_profile")==CLONE_SCAM_PROFILE and web.get("heuristic_auto_block") is False and web.get("mitm_https") is False and final.get("profile")==CLONE_SCAM_PROFILE and final.get("status")=="suspicious" and final.get("block_recommended") is False and ipc["passed"])
    result["passed"] = bool(result["local_passed"] and (not service_live or result["service_live_passed"]))
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description="BC Sentinel v0.10.0-rc.1 consolidation acceptance"); parser.add_argument("--service-live",action="store_true"); parser.add_argument("--output",type=Path); args=parser.parse_args(); result=run(service_live=args.service_live); text=json.dumps(result,ensure_ascii=False,indent=2); print(text)
    if args.output: args.output.write_text(text+"\n",encoding="utf-8")
    return 0 if result.get("passed") else 2

if __name__ == "__main__": raise SystemExit(main())