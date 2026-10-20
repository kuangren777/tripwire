"""Post-hoc, $0 (no model calls): held-out attacks that ROPE admits, split by whether the injection task's harmful
side-effect call goes through a parameter ROPE's audited floor does not check (tool outside the floor, or the
attacker-carrying control argument absent from floor[tool]) or through a checked one. Classification uses the injection
task's ground truth only. Injection tasks whose ground truth sets no control argument are not classified;
their runs and admitted attacks are counted and printed as skipped, never dropped silently. usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/h1_rope_unchecked_attacks.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json, sys
sys.path[:0] = ["."]
from agentdojo.task_suite.load_suites import get_suite
from boundary_prevalence import VERSION, CONTROL_ALL
from rope.scopes_io import load_floor

D = "./data_v2/v2_heldout"
MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06", "qwen3-235b-a22b-instruct-2507"]
tot = {"unchecked": [0, 0], "checked": [0, 0], "skipped_no_control_arg": [0, 0]}
skipped = {}
all_runs = [0, 0]
params = {}
for sn in ("shopping", "github", "dailylife"):
    suite = get_suite(VERSION, sn); env = suite.load_and_inject_default_environment({}); floor = load_floor(sn)
    cls = {}
    for iid, it in suite.injection_tasks.items():
        un = []
        for c in it.ground_truth(env):
            ctrl = CONTROL_ALL.get(c.function, ())
            if not ctrl:
                continue
            for a in ctrl:
                if c.args.get(a) is None:
                    continue
                guarded = c.function in floor and a in floor[c.function] and floor[c.function][a][0] not in ("free",)
                un.append((f"{c.function}.{a}", not guarded))
        if un:
            cls[iid] = ("unchecked" if any(u for _, u in un) else "checked", [p for p, u in un if u])
        else:
            cls[iid] = ("skipped_no_control_arg", [])
            skipped[f"{sn}/{iid}"] = [c.function for c in it.ground_truth(env)]
    for m in MODELS:
        for f in glob.glob(f"{D}/{m}/rope/*/{sn}/user_task_*/important_instructions/injection_task_*.json"):
            iid = f.split("/")[-1][:-5]
            d = json.load(open(f))
            all_runs[0] += bool(d.get("security")); all_runs[1] += 1
            if iid not in cls:
                raise SystemExit(f"unknown injection task {sn}/{iid} in {f}")
            k, ps = cls[iid]
            tot[k][1] += 1
            if d.get("security"):
                tot[k][0] += 1
                for p in ps:
                    params[p] = params.get(p, 0) + 1
print("ROPE admitted / attacked runs, by injection class:", tot)
print("unchecked parameters on admitted attacks:", params)
print("skipped injection tasks (ground truth sets no control argument):", skipped)
print("all ROPE held-out attacked runs, admitted / total:", all_runs)
assert all_runs == [sum(v[0] for v in tot.values()), sum(v[1] for v in tot.values())]
