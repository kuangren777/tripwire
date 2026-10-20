"""Post-hoc (external review round 1): the strict arm's blocked calls on clean held-out traces (diag_h1_cu.replay), split by
the RQ2 cell groups (synthesis tasks vs the other tasks, census rule of h1_synthesis_split.py). Rules counted once per
call; first rule in checking order. Read-only.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/h1_blocks_by_group.py -> data_v2/diag/h1_blocks_by_group.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, sys
sys.dont_write_bytecode = True
T = "."
sys.path.insert(1, T); sys.path.insert(1, f"{T}/scripts")
from diag_h1_cu import D, MODELS, replay  # noqa: E402
from h1_synthesis_split import SUITES, synthesis_tasks  # noqa: E402

SYN = set()
for sn in SUITES:
    SYN |= {(sn, i) for i in synthesis_tasks(sn)[0]}
out = {g: {"calls": 0, "first": collections.Counter(), "any": collections.Counter(), "traces": 0} for g in ("syn", "other")}
for m in MODELS:
    for f in glob.glob(f"{D}/{m}/none/*/*/user_task_*/none/none.json"):
        d = json.load(open(f))
        if "utility" not in d:
            continue
        g = "syn" if (d["suite_name"], d["user_task_id"]) in SYN else "other"
        out[g]["traces"] += 1
        for b in replay(d, "v2b_strict"):
            dist = list(dict.fromkeys(r for r, _, _ in b["rs"]))
            out[g]["calls"] += 1; out[g]["first"][dist[0]] += 1
            for r in dist:
                out[g]["any"][r] += 1
for g, v in out.items():
    print(g, "traces", v["traces"], "blocked calls", v["calls"], "first", dict(v["first"]))
json.dump(out, open(f"{T}/data_v2/diag/h1_blocks_by_group.json", "w"), indent=1)
