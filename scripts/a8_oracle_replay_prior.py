"""CANCELLED with Amendment 8; uses the superseded census rule. Amendment 8 prior (written before any run): $0 replay of the held-out no-defense CLEAN traces of gpt-4o-mini and
gpt-4o through v2b_strict. A cell counts as oracle-recoverable when the no-defense run completes the task and every
call strict would block is blocked only on control-argument values that the census marks as synthesized for that
task (ground-truth control values absent from the prompt and the clean environment). Read-only.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/a8_oracle_replay_prior.py  (from paper-tripwire/)"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, sys
sys.dont_write_bytecode = True
T = "."
sys.path.insert(1, T); sys.path.insert(1, f"{T}/scripts")
from diag_h1_cu import D, SUITES, replay  # noqa: E402
from boundary_prevalence import CONTROL_ALL, env_text  # noqa: E402

def oracle_values(sn):
    suite = SUITES[sn]; env = suite.load_and_inject_default_environment({}); E = env_text(env); out = {}
    for uid, t in suite.user_tasks.items():
        p = t.PROMPT.lower()
        try:
            gt = t.ground_truth(env)
        except Exception:  # noqa: BLE001
            continue
        vs = set()
        for c in gt:
            for a in CONTROL_ALL.get(c.function, ()):
                v = c.args.get(a)
                for x in (v if isinstance(v, (list, tuple)) else [v]):
                    x = str(x)
                    if len(x) >= 3 and x.lower() not in p and x.lower() not in E:
                        vs.add(x.lower())
        if vs:
            out[uid] = vs
    return out

OV = {sn: oracle_values(sn) for sn in SUITES}
print("synthesis tasks:", {sn: len(v) for sn, v in OV.items()}, "total", sum(len(v) for v in OV.values()))
c = collections.Counter()
for model in ("gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06"):
    for f in glob.glob(f"{D}/{model}/none/*/*/user_task_*/none/none.json"):
        d = json.load(open(f)); sn, uid = d["suite_name"], d["user_task_id"]
        if uid not in OV[sn]:
            continue
        c["syn_cells"] += 1
        if not d.get("utility"):
            continue
        c["syn_nodef_complete"] += 1
        bl = list(replay(d, "v2b_strict"))
        if not bl:
            c["strict_no_block"] += 1; continue
        vals = [str(v).lower() for b in bl for _, _, v in b["rs"]]
        c["oracle_recoverable" if vals and all(any(v == o or v in o or o in v for o in OV[sn][uid]) for v in vals) else "other_block"] += 1
print(dict(c))
