"""S7 check b scoring (AMENDMENT_s7.md): stability of 64 grid cells over the recorded run and three repeats.
usage: python3 analysis/s7_b_score.py -> data_v2/s7/b_repeat_score.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, json, os, sys

T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(T, "analysis"))
from s7_a_bridge import control_key, key, traj  # noqa: E402
from s7_b_repeat import CELLS, PRICE, tasks  # noqa: E402
from s7_common import wilson  # noqa: E402

MODELS = list(PRICE)


def load(root, cond, model, arm, row):
    f = os.path.join(root, f"e2x_{cond}", model, arm, f"{model}-{arm}", row["suite"], row["id"], f"e2x_{cond}", "none.json")
    return json.load(open(f)) if os.path.exists(f) else None


def outcome(d, cond):
    return bool(d["utility"] if cond == "a" else d["security"])


def main():
    calls = [json.loads(l) for l in open(os.path.join(T, "data_v2/s7/repeat_calls.jsonl"))]
    bad = {(c["rep"], c["cond"], c["arm"], c["task"], c["requested"]) for c in calls if not c["served_ok"]}
    rows, flips, nrep, pair_call, pair_ctl = [], 0, 0, 0, 0
    for model in MODELS:
        for cond, arm in CELLS:
            for row in tasks():
                runs = [load(os.path.join(T, "data_v2"), cond, model, arm, row)] + \
                       [load(os.path.join(T, f"data_v2/s7/repeat_{k}"), cond, model, arm, row) for k in (1, 2, 3)]
                if any(r is None or "utility" not in r for r in runs):
                    continue
                outs = [outcome(r, cond) for r in runs]
                keys = [key(traj(r)[0]) for r in runs]
                ckeys = [control_key(traj(r)[0]) for r in runs]   # post hoc, parallel to check a's control-argument agreement
                flips += sum(o != outs[0] for o in outs[1:])
                pair_call += sum(k == keys[0] for k in keys[1:])      # post hoc: two-run agreement, the unit of check a
                pair_ctl += sum(k == ckeys[0] for k in ckeys[1:])
                nrep += 3
                rows.append({"model": model, "cond": cond, "arm": arm, "task": row["id"], "outcomes": outs,
                             "out_stable": len(set(outs)) == 1, "traj_stable": len(set(keys)) == 1, "ctl_stable": len(set(ckeys)) == 1,
                             "distinct_traj": len(set(keys)),
                             "served_flag": any((k, cond, arm, row["id"], model) in bad for k in (1, 2, 3))})
    W = lambda k, n: {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else None, "wilson": [round(100 * x, 1) for x in wilson(k, n)]}
    res = {"cells": len(rows), "repeat_runs": nrep, "served_flagged_cells": sum(r["served_flag"] for r in rows),
           "served_names": dict(collections.Counter(c["served"] for c in calls)),
           "spend_usd": round(sum((c["prompt_tokens"] * PRICE[c["requested"]][0] + c["completion_tokens"] * PRICE[c["requested"]][1]) / 1e6 for c in calls), 3),
           "max_prompt_tokens": max(c["prompt_tokens"] for c in calls),
           "outcome_stable": W(sum(r["out_stable"] for r in rows), len(rows)),
           "trajectory_stable": W(sum(r["traj_stable"] for r in rows), len(rows)),
           "control_stable_post_hoc": W(sum(r["ctl_stable"] for r in rows), len(rows)),
           "pairwise_calls_post_hoc": W(pair_call, nrep), "pairwise_control_post_hoc": W(pair_ctl, nrep),
           "outcome_flips_vs_recorded": {"k": flips, "n": nrep},
           "by_model_cond": {}}
    for model in MODELS:
        for cond, arm in CELLS:
            R = [r for r in rows if r["model"] == model and r["cond"] == cond and r["arm"] == arm]
            res["by_model_cond"][f"{model}|{cond}|{arm}"] = {"cells": len(R), "out_stable": sum(r["out_stable"] for r in R),
                                                           "traj_stable": sum(r["traj_stable"] for r in R), "ctl_stable": sum(r["ctl_stable"] for r in R),
                                                           "distinct_traj_hist": dict(collections.Counter(r["distinct_traj"] for r in R))}
    res["unstable_outcome_cells"] = [r for r in rows if not r["out_stable"]]
    json.dump(res, open(os.path.join(T, "data_v2/s7/b_repeat_score.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k not in ("unstable_outcome_cells",)}, indent=1))
    for r in res["unstable_outcome_cells"]:
        print("unstable", r["model"], r["cond"], r["arm"], r["task"], r["outcomes"])


if __name__ == "__main__":
    main()
