"""Run the pipeline on a dataset and save raw results.
Usage: PYTHONPATH=. python eval/run_eval.py DATASET.csv RESULTS.json"""
import csv
import json
import re
import sys
import time

from beawake.checker import check

try:
    from beawake.signals import rules_verdict
except ImportError:  # older signals module without rules_verdict

    def rules_verdict(signals):
        return "suspicious" if set(signals) - {"link"} else "safe"


LOOP = re.compile(r"(.{2,12}?)\1{4,}")  # a short chunk repeated 5+ times = collapsed answer
SPANISH = re.compile(r"\b(el|los|las|mensaje|enlace|este|esta|haga|clic|no hagas)\b", re.I)
ARABIC = re.compile(r"[\u0600-\u06FF]")


def wrong_lang(lang: str, text: str) -> bool:
    if lang == "ar":
        return not ARABIC.search(text)
    return bool(ARABIC.search(text) or SPANISH.search(text))


src, dst = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(src, encoding="utf-8")))
results, start = [], time.time()
for i, row in enumerate(rows, 1):
    full = check(row["text"])
    out = f"{full['reason']} {full['action']}"
    results.append({
        **row,
        "signals": full["signals"],
        "rules": rules_verdict(full["signals"]),
        "gemma": full["model_verdict"],
        "full": full["verdict"],
        "broken": bool(LOOP.search(full["raw"]) or not full["reason"] or not full["action"]),
        "wrong_lang": wrong_lang(row["lang"], out),
        "raw": full["raw"],
    })
    print(f"{i}/{len(rows)} done ({time.time() - start:.0f}s)", flush=True)
json.dump(results, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

LANGS = ("tr", "ar", "en")
print("\n| lang | system | missed scams | false alarms |\n|---|---|---|---|")
for lang in (*LANGS, "all"):
    rs = [r for r in results if lang == "all" or r["lang"] == lang]
    for system in ("rules", "gemma", "full"):
        scams = [r for r in rs if r["label"] == "scam"]
        safes = [r for r in rs if r["label"] == "safe"]
        print(f"| {lang} | {system} | {sum(r[system] == 'safe' for r in scams)}/{len(scams)} "
              f"| {sum(r[system] != 'safe' for r in safes)}/{len(safes)} |")
print("\nBroken answers:", {l: sum(r["broken"] for r in results if r["lang"] == l) for l in LANGS})
print("Wrong reply language:", {l: sum(r["wrong_lang"] for r in results if r["lang"] == l) for l in LANGS})
raised = [r for r in results if r["full"] != r["gemma"]]
print(f"Safety floor raised {len(raised)} verdicts ({sum(r['label'] == 'scam' for r in raised)} were real scams).")
