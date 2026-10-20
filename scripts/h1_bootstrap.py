"""Amendment 4, section 6.3: paired task-cluster bootstrap intervals for the H1 held-out gaps. Read-only.
Gaps pooled over the 3 held-out models:
  security = ASR(arm) - ASR(rope) on attacked cells (ROPE's corrected security, as in v2_h1_decision.py;
  the raw field was used before 2026-10-14 and gives identical results for these three configurations);
  utility  = CU(rope) - CU(arm) on clean cells (utility field).
Clusters are (suite, user task): every cell of a task, all models and all injections, moves together.
10,000 resamples, seed 0, percentile 95% interval.
usage: python3 scripts/h1_bootstrap.py  (from paper-tripwire/) -> data_v2/v2_heldout/bootstrap.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, random, re, sys

T = "."
sys.path.insert(0, "ext/rope/runs")
from corrections import corrected_security  # noqa: E402


def corrected(d, suite, fname):
    """ROPE's effect-based ASR correction (ext/rope/runs/corrections.py), applied to every configuration alike."""
    return bool(corrected_security(d, suite, int(re.sub(r"\D", "", fname[:-5]) or -1)))
D = f"{T}/data_v2/v2_heldout"
MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06", "qwen3-235b-a22b-instruct-2507"]
ARMS = ["rope", "tripwire_strict_v2", "tripwire_v2"]
B, SEED = 10_000, 0


def load():
    """cells[arm][(model, suite, task, attack, file)] = (is_clean, outcome); same path parsing as v2_h1_decision."""
    cells = {a: {} for a in ARMS}
    for a in ARMS:
        for m in MODELS:
            for f in glob.glob(f"{D}/{m}/{a}/*/*/user_task_*/*/*.json"):
                p = f.split("/")
                d = json.load(open(f))
                if "utility" not in d:
                    raise SystemExit(f"unfinished cell {f}")
                clean = p[-2] == "none"
                cells[a][(m, p[-4], p[-3], p[-2], p[-1])] = (clean, bool(d["utility"]) if clean else corrected(d, p[-4], p[-1]))
    return cells


def gaps(cells, arm, keys_by_task, tasks):
    sec = [0, 0, 0]   # arm successes, rope successes, n
    cu = [0, 0, 0]    # rope completions, arm completions, n
    for t in tasks:
        for k in keys_by_task[t]:
            clean, r = cells["rope"][k]
            _, x = cells[arm][k]
            if clean:
                cu[0] += r; cu[1] += x; cu[2] += 1
            else:
                sec[0] += x; sec[1] += r; sec[2] += 1
    return 100 * (sec[0] - sec[1]) / sec[2], 100 * (cu[0] - cu[1]) / cu[2]


def main():
    cells = load()
    common = set(cells["rope"])
    for a in ARMS[1:]:
        assert set(cells[a]) == common, f"cell sets differ for {a}"
    keys_by_task = collections.defaultdict(list)
    for k in sorted(common):
        keys_by_task[(k[1], k[2])].append(k)
    tasks = sorted(keys_by_task)
    rng = random.Random(SEED)
    out = {"n_tasks": len(tasks), "n_cells": len(common), "B": B, "seed": SEED}
    for arm in ARMS[1:]:
        s0, u0 = gaps(cells, arm, keys_by_task, tasks)
        ss, us = [], []
        for _ in range(B):
            draw = [tasks[rng.randrange(len(tasks))] for _ in tasks]
            s, u = gaps(cells, arm, keys_by_task, draw)
            ss.append(s); us.append(u)
        ss.sort(); us.sort()
        lo, hi = int(0.025 * B), int(0.975 * B) - 1
        out[arm] = {"security_gap_pp": round(s0, 2), "security_ci": [round(ss[lo], 2), round(ss[hi], 2)],
                    "utility_gap_pp": round(u0, 2), "utility_ci": [round(us[lo], 2), round(us[hi], 2)]}
        print(f"{arm:20} security {s0:+6.2f} pp [{ss[lo]:+.2f}, {ss[hi]:+.2f}]   "
              f"utility {u0:+6.2f} pp [{us[lo]:+.2f}, {us[hi]:+.2f}]")
    json.dump(out, open(f"{D}/bootstrap.json", "w"), indent=1)


if __name__ == "__main__":
    main()
