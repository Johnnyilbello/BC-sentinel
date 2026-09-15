"""Display-only translations. Never mutate evidence or security decisions."""
import re


def product_text(value: str, fallback: str = "Dettagli tecnici disponibili nei Dettagli avanzati") -> str:
    text = str(value or "")
    text = text.replace("Static scanner assessment: temp_execution_candidate", "Comportamento sospetto rilevato in una cartella temporanea")
    text = text.replace("static_malware_scan", "Analisi malware")
    text = re.sub(r"smart_scope_\d+", "Scansione intelligente", text)
    # Unknown provider codes must remain available in the original evidence,
    # without presenting implementation identifiers as product explanations.
    if re.search(r"\b\w+_\w+\b|\bB6-\d", text):
        return fallback
    return text


def source_label(value: str) -> str:
    return {"files": "Analisi dei file", "processes": "Analisi dei processi", "startup": "Programmi di avvio", "network": "Analisi di rete"}.get(value, product_text(value, "Controllo di sicurezza"))
