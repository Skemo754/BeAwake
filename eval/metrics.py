"""Accuracy, precision, recall with a 95% Wilson interval. Usage: python eval/metrics.py RESULTS.json"""
import json
import sys
from math import sqrt

R = json.load(open(sys.argv[1], encoding="utf-8"))


def wilson(k, n, z=1.96):
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def div(a, b):
    return f"{100 * a / b:.0f}%" if b else "-"


print("| lang | system | accuracy | 95% CI | precision | recall |\n|---|---|---|---|---|---|")
for lang in ("tr", "ar", "en", "all"):
    rs = [r for r in R if lang == "all" or r["lang"] == lang]
    for s in ("rules", "gemma", "full"):
        tp = sum(r[s] != "safe" and r["label"] == "scam" for r in rs)
        fp = sum(r[s] != "safe" and r["label"] == "safe" for r in rs)
        fn = sum(r[s] == "safe" and r["label"] == "scam" for r in rs)
        tn = sum(r[s] == "safe" and r["label"] == "safe" for r in rs)
        lo, hi = wilson(tp + tn, len(rs))
        print(f"| {lang} | {s} | {div(tp + tn, len(rs))} ({tp + tn}/{len(rs)}) | {100 * lo:.0f}-{100 * hi:.0f}% "
              f"| {div(tp, tp + fp)} | {div(tp, tp + fn)} |")
