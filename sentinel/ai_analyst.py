from __future__ import annotations
import json
from urllib import request

SYSTEM="""Sei l'analista di BC Sentinel. Spiega in italiano semplice perché un evento è rischioso.
Usa soltanto le evidenze presenti nell'input. Non suggerire comandi shell, non decidere azioni di sicurezza,
non modificare lo score e non inventare fatti. Massimo 4 frasi."""

class OllamaAnalyst:
    def __init__(self,model="qwen3:4b",endpoint="http://127.0.0.1:11434/api/chat"):
        self.model=model; self.endpoint=endpoint

    @property
    def base_url(self):
        return self.endpoint.split("/api/",1)[0]+"/api" if "/api/" in self.endpoint else self.endpoint.rstrip("/")

    def health(self,timeout=2.0):
        try:
            with request.urlopen(self.base_url+"/tags",timeout=timeout) as resp:data=json.loads(resp.read().decode())
            return {"ok":True,"models":[x.get("name","") for x in data.get("models",[]) if x.get("name")]}
        except Exception as exc:return {"ok":False,"models":[],"error":str(exc)}

    def explain(self,payload,timeout=8.0):
        body=json.dumps({"model":self.model,"stream":False,"messages":[{"role":"system","content":SYSTEM},{"role":"user","content":json.dumps(payload,ensure_ascii=False)}],"options":{"temperature":0.2}}).encode()
        req=request.Request(self.endpoint,data=body,headers={"Content-Type":"application/json"})
        try:
            with request.urlopen(req,timeout=timeout) as resp:data=json.loads(resp.read().decode())
            return data.get("message",{}).get("content")
        except Exception:return None
