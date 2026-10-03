"""List every message a system got wrong. Usage: python eval/errors.py RESULTS.json"""
import json
import sys

for r in json.load(open(sys.argv[1], encoding="utf-8")):
    wrong = {s: r[s] for s in ("rules", "gemma", "full") if (r[s] == "safe") != (r["label"] == "safe")}
    if wrong or r["wrong_lang"] or r["broken"]:
        flags = [k for k in ("wrong_lang", "broken") if r[k]]
        print(r["id"], r["label"], wrong, flags or "", "|", r["text"][:60])
