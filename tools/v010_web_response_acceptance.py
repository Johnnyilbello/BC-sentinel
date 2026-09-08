from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend
from sentinel.protection_client import ProtectionServiceClient
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine
from sentinel.web_response import WEB_RESPONSE_PROFILE, qualify_web_containment


def _runtime(root: Path, backend=None) -> ProtectionRuntime:
    root.mkdir(parents=True, exist_ok=True)
    r=ProtectionRuntime.__new__(ProtectionRuntime)
    r.db=Database(root/'beta2-acceptance.sqlite')
    r.web_protection=WebProtectionEngine(r.db)
    r.dns_cache=DNSCorrelationCache(ttl_seconds=120)
    r.firewall=FirewallManager(backend or InMemoryFirewallBackend(), desired_state_store=r.db)
    return r


def _ioc(db, kind, value):
    db.execute("""INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
                  VALUES(?,?,?,?,?,?)""",(kind,value,'critical','harmless Beta2 fixture',time.time()+3600,'v010-beta2-acceptance'))


def _finding(r, fid, *, domain='malware.test', address='192.0.2.55', pid=4242, source='signed_ioc_domain', score=90, block=True, shared=False):
    r.db.record_web_finding(
        finding_id=fid,created_at=time.time(),domain=domain,remote_address=address,pid=pid,process_name='chrome.exe',
        process_path='C:/browser.exe',score=score,level='CRITICAL' if score>=90 else 'LOW',source=source,
        reasons_json='["harmless fixture"]',evidence_json='{"event_category":"network","dns_correlated":true}',
        shared_ip=shared,block_recommended=block,decision='containment_recommended' if block else 'review',dedupe_seconds=1,
    )


def run(*, service_live: bool=False) -> dict:
    checks={}
    detail={}
    with tempfile.TemporaryDirectory(prefix='bcs-v010-beta2-') as raw:
        root=Path(raw); r=_runtime(root); _ioc(r.db,'domain','malware.test')
        r.dns_cache.observe(4242,'malware.test',['192.0.2.55'])
        fid='BCW-'+'A'*20; _finding(r,fid)
        lease=r.create_web_containment({'finding_id':fid,'ttl_seconds':60,'approved':True,'reason':'acceptance'})
        checks['signed_ioc_block']=lease.get('qualification')=='signed_domain_nonshared_ip' and len(r.firewall.list_rules())==1
        second=r.create_web_containment({'finding_id':fid,'ttl_seconds':60,'approved':True})
        checks['duplicate_rule_prevention']=second.get('lease_id')==lease.get('lease_id') and len(r.firewall.list_rules())==1
        released=r.release_containment_lease(lease['lease_id'],approved=True)
        checks['manual_rollback']=released.get('removed') is True and r.firewall.list_rules()==[]

        trust=_runtime(root/'trust'); _ioc(trust.db,'domain','malware.test'); trust.db.add_web_domain_trust('malware.test',reason='older trust')
        trust.dns_cache.observe(4242,'malware.test',['192.0.2.55']); tf='BCW-'+'B'*20; _finding(trust,tf)
        ta=trust.web_protection.assess_domain('malware.test')
        tl=trust.create_web_containment({'finding_id':tf,'ttl_seconds':60,'approved':True})
        checks['signed_ioc_overrides_trust']=ta.signed_ioc and ta.trusted_domain and tl.get('qualification')=='signed_domain_nonshared_ip'

        heur=_runtime(root/'heur'); hf='BCW-'+'C'*20; _finding(heur,hf,source='local_heuristics',score=49,block=False)
        denied=False
        try: heur.create_web_containment({'finding_id':hf,'ttl_seconds':60,'approved':True})
        except PermissionError: denied=True
        checks['heuristic_only_no_block']=denied and heur.firewall.list_rules()==[]

        shared=_runtime(root/'shared'); _ioc(shared.db,'domain','malware.test')
        shared.dns_cache.observe(4242,'malware.test',['192.0.2.55']); shared.dns_cache.observe(9009,'cdn.example',['192.0.2.55'])
        sf='BCW-'+'D'*20; _finding(shared,sf,shared=True); shared_denied=False
        try: shared.create_web_containment({'finding_id':sf,'ttl_seconds':60,'approved':True})
        except PermissionError: shared_denied=True
        checks['shared_cdn_no_global_block']=shared_denied and shared.firewall.list_rules()==[]

        wrong=_runtime(root/'pid'); _ioc(wrong.db,'domain','malware.test'); wrong.dns_cache.observe(9999,'malware.test',['192.0.2.55'])
        wf='BCW-'+'E'*20; _finding(wrong,wf,pid=4242); wrong_denied=False
        try: wrong.create_web_containment({'finding_id':wf,'ttl_seconds':60,'approved':True})
        except PermissionError: wrong_denied=True
        checks['same_pid_dns_connection_required']=wrong_denied

        ttl=_runtime(root/'ttl'); _ioc(ttl.db,'domain','malware.test'); ttl.dns_cache.observe(4242,'malware.test',['192.0.2.55'])
        xf='BCW-'+'F'*20; _finding(ttl,xf); xl=ttl.create_web_containment({'finding_id':xf,'ttl_seconds':60,'approved':True})
        ttl.db.execute('UPDATE containment_leases SET expires_at=? WHERE lease_id=?',(time.time()-1,xl['lease_id']))
        ex=ttl.expire_containment_leases(); checks['ttl_expiry']=bool(ex) and ttl.firewall.list_rules()==[]

        backend=InMemoryFirewallBackend(); rr=_runtime(root/'restart',backend); _ioc(rr.db,'domain','malware.test'); rr.dns_cache.observe(4242,'malware.test',['192.0.2.55'])
        rf='BCW-'+'1'*20; _finding(rr,rf); rl=rr.create_web_containment({'finding_id':rf,'ttl_seconds':300,'approved':True})
        rr2=_runtime(root/'restart',backend); recovery=rr2.recover_web_containment_state()
        checks['restart_recovery']=rl['lease_id'] in recovery['active'] and not recovery['stale']
        backend.remove_rule(rl['rule_id']); recovery2=rr2.recover_web_containment_state()
        checks['stale_rule_cleanup']=rl['lease_id'] in recovery2['stale'] and rr2.db.list_firewall_expected_rules()==[]

        policy=qualify_web_containment(source='local_heuristics',score=100,block_recommended=True,event_category='network',domain='x.example',remote_address='192.0.2.99',dns_domain='x.example')
        checks['heuristic_policy_fail_closed']=not policy.eligible and policy.reason=='heuristic_only_never_blocks'
        detail={'lease':lease,'recovery':recovery,'recovery_after_missing':recovery2}

    live_ok=True; service=None
    if service_live:
        client=ProtectionServiceClient(timeout=3.0)
        service=client.web_status()
        leases=client.containment_leases()
        live_ok=bool(isinstance(service,dict) and service.get('response_profile')==WEB_RESPONSE_PROFILE and service.get('shared_ip_guard') is True and service.get('heuristic_auto_block') is False and isinstance(leases,list))
        checks['service_live']=live_ok
    result={
        'product':'BC Sentinel','version':APP_VERSION,'milestone':'v0.10.0-beta.2','response_profile':WEB_RESPONSE_PROFILE,
        'acceptance':checks,'detail':detail,'service':service,'passed':all(checks.values()) and live_ok,
        'safety':{'mitm_https':False,'heuristic_auto_block':False,'cloud_required':False,'shared_ip_guard':True,'reversible_only':True},
    }
    return result


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument('--service-live',action='store_true'); ap.add_argument('--output',type=Path); args=ap.parse_args()
    result=run(service_live=args.service_live); text=json.dumps(result,indent=2,ensure_ascii=False); print(text)
    if args.output: args.output.write_text(text+'\n',encoding='utf-8')
    return 0 if result.get('passed') else 2

if __name__=='__main__': raise SystemExit(main())
