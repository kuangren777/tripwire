"""Amendment 7 (R2c) stage 1 analysis, fixed before any run. share = (routed - fixed) / (routed - strict), clean cells,
gpt-4o-mini and gpt-4o, all from the same batch (data_v2/r2c). 95% percentile CI from 10,000 bootstrap resamples of the
60 held-out tasks (each task keeps both model cells), seed 0. Decision on the CI: lo >= 0.5 case 1, hi <= 0.2 case 2,
otherwise case 3. Error cells (non-empty 'error' or missing files) are reported and the analysis refuses to decide.
Old logs (data_v2/v2_heldout) are printed as a reference only. usage: python3 scripts/r2c_share.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json, random
T = "."
MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06"]; CONDS = ["rope", "rope_fixed", "tripwire_strict_v2"]
def cells(root, cond):
    out, err = {}, []
    for m in MODELS:
        for f in glob.glob(f"{root}/{m}/{cond}/*/*/user_task_*/none/none.json"):
            d = json.load(open(f)); k = (f.split("/")[-4], d["user_task_id"])
            if d.get("error"): err.append((m, k, str(d["error"])[:80]))
            out[(m,) + k] = bool(d.get("utility"))
    return out, err
new = {c: cells(f"{T}/data_v2/r2c", c) for c in CONDS}
errs = [e for c in CONDS for e in new[c][1]]
tasks = sorted({k[1:] for k in new["rope"][0]})
n = {c: len(new[c][0]) for c in CONDS}
print("cells per condition:", n, "error cells:", len(errs))
for e in errs[:20]: print("  ERROR", e)
def share(ts):
    R = sum(new["rope"][0].get((m,) + t, False) for t in ts for m in MODELS)
    F = sum(new["rope_fixed"][0].get((m,) + t, False) for t in ts for m in MODELS)
    S = sum(new["tripwire_strict_v2"][0].get((m,) + t, False) for t in ts for m in MODELS)
    return R, F, S, ((R - F) / (R - S) if R != S else float("nan"))
R, F, S, sh = share(tasks)
print(f"batch counts over {len(tasks)} tasks x 2 models: routed {R}, fixed {F}, strict {S}; share {sh:.3f}")
rng = random.Random(0); bs = []
for _ in range(10000):
    v = share([rng.choice(tasks) for _ in tasks])[3]
    if v == v: bs.append(v)
bs.sort(); lo, hi = bs[int(0.025 * len(bs))], bs[int(0.975 * len(bs)) - 1]
print(f"share 95% CI {lo:.3f} to {hi:.3f} ({len(bs)} valid resamples)")
for m in MODELS:
    print(m, {c: sum(v for k, v in new[c][0].items() if k[0] == m) for c in CONDS})
old = {c: cells(f"{T}/data_v2/v2_heldout", c)[0] for c in ("rope", "tripwire_strict_v2")}
print("reference, old logs:", {c: sum(old[c].values()) for c in old}, "of", {c: len(old[c]) for c in old})
if errs or any(n[c] != 120 for c in CONDS):
    print("DECISION: none (error or missing cells)")
else:
    print("DECISION: case", 1 if lo >= 0.5 else 2 if hi <= 0.2 else 3)
