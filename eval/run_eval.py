"""Compare three systems on eval/dataset.csv: rules only, Gemma only, full pipeline."""
import csv
import json
import re
import time

from beawake.checker import check
from beawake.llm import check_message
from beawake.signals import find_signals

LOOP = re.compile(r"(.{2,12}?)\1{4,}")  # same short chunk repeated 5+ times

rows = list(csv.DictReader(open("eval/dataset.csv", encoding="utf-8")))
results, start = [], time.time()
for i, row in enumerate(rows, 1):
    text = row["text"]
    signals = find_signals(text)
    full = check(text)
    results.append({
        **row,
        "signals": signals,
        "rules": "suspicious" if set(signals) - {"link"} else "safe",
        "gemma": full["model_verdict"],
        "full": full["verdict"],
        "full_model": full["model_verdict"],
        "broken": bool(LOOP.search(full["raw"]) or not full["reason"] or not full["action"]),
        "raw": full["raw"],
    })
    print(f"{i}/{len(rows)} done ({time.time() - start:.0f}s)", flush=True)

json.dump(results, open("eval/results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def rate(rs, system):
    scams = [r for r in rs if r["label"] == "scam"]
    safes = [r for r in rs if r["label"] == "safe"]
    missed = sum(r[system] == "safe" for r in scams)
    false = sum(r[system] != "safe" for r in safes)
    return f"{missed}/{len(scams)}", f"{false}/{len(safes)}"


print("\n| lang | system | missed scams | false alarms |\n|---|---|---|---|")
for lang in ("tr", "ar", "en", "all"):
    rs = [r for r in results if lang == "all" or r["lang"] == lang]
    for system in ("rules", "gemma", "full"):
        print(f"| {lang} | {system} | {' | '.join(rate(rs, system))} |")

print("\nBroken answers in full pipeline:",
      {lang: sum(r["broken"] for r in results if r["lang"] == lang) for lang in ("tr", "ar", "en")})
raised = [r for r in results if r["full"] != r["full_model"]]
print(f"Safety floor raised {len(raised)} verdicts ({sum(r['label'] == 'scam' for r in raised)} were real scams).")
