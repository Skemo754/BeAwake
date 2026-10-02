"""Thin client for a local llama-server running Gemma."""
import re
import requests

URL = "http://127.0.0.1:8080/v1/chat/completions"

SYSTEM = (
    "You check whether a message (SMS, WhatsApp, email) is a scam. "
    "Answer in exactly three lines:\n"
    "VERDICT: safe, suspicious or scam (when unsure, suspicious)\n"
    "REASON: one short sentence\n"
    "ACTION: one short instruction\n"
    "Write REASON and ACTION in the same language as the message."
)


def _field(name: str, raw: str) -> str:
    m = re.search(rf"{name}:\s*(.+)", raw, re.I)
    return m.group(1).strip() if m else ""


def check_message(text: str, url: str = URL) -> dict:
    payload = {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": text},
        ],
        "chat_template_kwargs": {"enable_thinking": False},
        "temperature": 0,
        "seed": 42,
        "max_tokens": 200,
    }
    try:
        r = requests.post(url, json=payload, timeout=120)
        r.raise_for_status()
    except requests.ConnectionError:
        raise RuntimeError(f"llama-server is not reachable at {url}") from None
    raw = r.json()["choices"][0]["message"]["content"]
    m = re.search(r"\b(safe|suspicious|scam)\b", _field("VERDICT", raw).lower())
    return {
        "verdict": m.group(1) if m else "suspicious",
        "reason": _field("REASON", raw),
        "action": _field("ACTION", raw),
        "raw": raw,
    }
