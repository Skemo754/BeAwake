import json

for r in json.load(open("eval/results.json", encoding="utf-8")):
    wrong = {s: r[s] for s in ("rules", "gemma", "full") if (r[s] == "safe") != (r["label"] == "safe")}
    if wrong:
        print(r["id"], r["label"], wrong, "|", r["text"][:70])
