"""Rules-only evaluation (no model). Usage: python eval/rules_only.py DATASET.csv [signals_v1.py]"""
import csv, importlib.util, sys
sys.path.insert(0, ".")

def load(path):
    spec = importlib.util.spec_from_file_location("sig", path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

mod = load(sys.argv[2]) if len(sys.argv) > 2 else load("beawake/signals.py")
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8")))
wrong = []
tot = {}
for r in rows:
    s = mod.find_signals(r["text"]); v = mod.rules_verdict(s)
    bad = (v == "safe") != (r["label"] == "safe")
    k = tot.setdefault(r["lang"], [0, 0, 0, 0])  # n, missed scams, false alarms, correct
    k[0] += 1; k[3] += (not bad)
    if bad:
        k[1 if r["label"] == "scam" else 2] += 1
        wrong.append((r["id"], r["label"], v, s, r["text"][:60]))
n = sum(k[0] for k in tot.values()); c = sum(k[3] for k in tot.values())
print({l: f"acc {k[3]}/{k[0]} missed {k[1]} false {k[2]}" for l, k in tot.items()}, f"| ALL {c}/{n}")
for w in wrong: print(" ", *w)
