"""Post-hoc, $0 (no model calls): on every held-out clean cell ROPE completes, does the cached router scope change the
policy that governs the sensitive calls the trajectory executed? compile_policy differs from the floor only through
scope.overrides (per-parameter rules) and scope.named_source (delegated trust). A cell is router-independent when no
executed sensitive (tool, arg) has an override and the scope names no source. Replay assumes the trajectory would not
change under the floor-only policy. usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/h1_router_dependence.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json, sys
from collections import Counter
sys.path[:0] = ["./scripts", "."]
import h1_synthesis_split as H
from agentdojo.task_suite.load_suites import get_suite
from boundary_prevalence import VERSION
from rope.scopes_io import load_router_scopes
D = "./data_v2/v2_heldout"
tot = Counter(); rows = []
for sn in H.SUITES:
    floor, scopes = load_router_scopes("opus", sn)
    suite = get_suite(VERSION, sn)
    syn = H.synthesis_tasks(sn)[0]
    for m in H.MODELS:
        for f in glob.glob(f"{D}/{m}/rope/*/{sn}/user_task_*/none/none.json"):
            d = json.load(open(f)); uid = d["user_task_id"]
            tot["clean_cells"] += 1
            if not d.get("utility"):
                continue
            tot["rope_completed"] += 1
            sc = scopes.get(suite.user_tasks[uid].PROMPT)
            if sc is None:
                tot["no_cached_scope"] += 1; rows.append((m, sn, uid, "NO SCOPE")); continue
            calls = [(t["function"], a) for x in d["messages"] for t in (x.get("tool_calls") or []) for a in (t.get("args") or {})]
            sens = [(fn, a) for fn, a in calls if fn in floor and a in floor[fn]]
            ov = sorted({f"{fn}.{a}" for fn, a in sens if a in sc.overrides.get(fn, {})})
            ns = bool(sc.named_source) and bool(sens)
            k = "router_dependent" if (ov or ns) else "router_independent"
            tot[k] += 1; tot[k + ("_synthesis" if uid in syn else "_other")] += 1
            if k == "router_dependent":
                rows.append((m, sn, uid, f"overrides={ov} named_source={sc.named_source if ns else None}"))
print(dict(tot))
for r in rows:
    print(*r)
