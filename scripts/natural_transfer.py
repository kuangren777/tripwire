"""Analysis of the natural-task transfer check (ANALYSIS_LOG.md, pre-registered 2530905f2). Read-only.
Reads data/v2_natural/nat_{a,b}/<model>/<arm>/<model>-<arm>/<suite>/<task>/nat_{a,b}/none.json and prints
  - per arm x condition, pooled over models and per model: a = utility (completion), b = attack success;
  - per task x arm, a and b, counted over the three models;
  - error rows (logged exceptions), which count as failed runs as in E2X.
Every expected cell must exist; a missing cell aborts.
usage: python3 scripts/natural_transfer.py"""
import json
import sys
from pathlib import Path

T = Path(".")
NAT = T / "data/v2_natural"
ARMS = ("none", "rope", "tripwire_v2", "tripwire_strict_v2")
MODELS = ("gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06", "qwen3-235b-a22b-instruct-2507")


def load():
    rows = json.load(open(NAT / "tasks.json"))
    out, missing = [], []
    for cond in ("a", "b"):
        for r in rows:
            if cond == "b" and not r["text_b"]:
                continue
            for m in MODELS:
                for arm in ARMS:
                    f = NAT / f"nat_{cond}" / m / arm / f"{m}-{arm}" / r["suite"] / r["id"] / f"nat_{cond}" / "none.json"
                    if not f.exists():
                        missing.append(str(f)); continue
                    d = json.loads(f.read_text())
                    out.append(dict(cond=cond, model=m, arm=arm, suite=r["suite"], task=r["id"],
                                    hit=bool(d["utility"] if cond == "a" else d["security"]),
                                    err=bool(d.get("error"))))
    return rows, out, missing


def main():
    rows, res, missing = load()
    if missing:
        print(f"MISSING {len(missing)} cells, e.g. {missing[:3]}"); sys.exit(1)

    def cnt(**kw):
        sel = [x for x in res if all(x[k] == v for k, v in kw.items())]
        return f"{sum(x['hit'] for x in sel)}/{len(sel)}"

    short = {"gpt-4o-mini-2024-07-18": "4o-mini", "gpt-4o-2024-08-06": "4o", "qwen3-235b-a22b-instruct-2507": "q235"}
    print("arm x condition (a = completion to the legitimate destination, b = admits of the inserted destination)")
    print(f"{'arm':20} {'cond':4} {'pooled':>7} " + " ".join(f"{short[m]:>7}" for m in MODELS))
    for arm in ARMS:
        for cond in ("a", "b"):
            print(f"{arm:20} {cond:4} {cnt(arm=arm, cond=cond):>7} " + " ".join(f"{cnt(arm=arm, cond=cond, model=m):>7}" for m in MODELS))
    print("\nper task (hits over the 3 models), columns a|b per arm")
    print(f"{'task':22} " + " ".join(f"{arm:>20}" for arm in ARMS))
    for r in rows:
        cells = []
        for arm in ARMS:
            a = cnt(arm=arm, cond="a", task=r["id"], suite=r["suite"])
            b = cnt(arm=arm, cond="b", task=r["id"], suite=r["suite"]) if r["text_b"] else "-"
            cells.append(f"{a} | {b}")
        print(f"{r['suite'][:5] + ' ' + r['id']:22} " + " ".join(f"{c:>20}" for c in cells))
    errs = [x for x in res if x["err"]]
    print(f"\nerror rows: {len(errs)} of {len(res)}")
    for x in errs:
        print("  ", x)


if __name__ == "__main__":
    main()
