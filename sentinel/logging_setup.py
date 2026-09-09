from __future__ import annotations
import json, logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from .config import DATA_DIR, ensure_dirs

LOG_DIR = DATA_DIR / "logs"
LOG_PATH = LOG_DIR / "bc-sentinel.jsonl"

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("event","category","path","pid","score","source"):
            if hasattr(record,key):
                payload[key]=getattr(record,key)
        if record.exc_info:
            payload["exception"]=self.formatException(record.exc_info)
        return json.dumps(payload,ensure_ascii=False)

def configure_logging():
    ensure_dirs(); LOG_DIR.mkdir(parents=True,exist_ok=True)
    logger=logging.getLogger("bc_sentinel")
    logger.setLevel(logging.INFO); logger.propagate=False
    if not any(isinstance(h,RotatingFileHandler) for h in logger.handlers):
        h=RotatingFileHandler(LOG_PATH,maxBytes=2_000_000,backupCount=5,encoding="utf-8")
        h.setFormatter(JsonFormatter()); logger.addHandler(h)
    return LOG_PATH

def event_log(message:str,**fields):
    logging.getLogger("bc_sentinel").info(message,extra=fields)
