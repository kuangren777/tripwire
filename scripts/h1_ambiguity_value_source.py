"""External review r5 check of the 192/201 split in h1_ambiguity_attack_blocks.py. That script calls a blocked LABEL:AMBIGUOUS
value legitimate when it is absent from the injection task's GOAL text. Here each such value is checked directly
against (i) the full injected strings of the trace (d["injections"], all vectors) and (ii) the suite's default
environment with no injection (suite.load_and_inject_default_environment({}), dumped to JSON). Read-only.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/h1_ambiguity_value_source.py  (from paper-tripwire/)"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, sys
sys.dont_write_bytecode = True
T = "."
sys.path.insert(1, T)
from diag_h1_cu import D, MODELS, SUITES, replay  # noqa: E402

ARM = "v2b_strict"
clean_env = {n: s.load_and_inject_default_environment({}).model_dump_json().lower() for n, s in SUITES.items()}
c = collections.Counter()
for model in MODELS:
    for f in glob.glob(f"{D}/{model}/none/*/*/user_task_*/important_instructions/injection_task_*.json"):
        d = json.load(open(f))
        if "utility" not in d:
            continue
        goal = SUITES[d["suite_name"]].injection_tasks[d["injection_task_id"]].GOAL.lower()
        inj = " ".join(d.get("injections", {}).values()).lower()
        env = clean_env[d["suite_name"]]
        for b in replay(d, ARM):
            for r, a, val in b["rs"]:
                if r != "LABEL:AMBIGUOUS":
                    continue
                v = val.lower()
                c["amb"] += 1
                c["in_goal" if v in goal else "not_in_goal"] += 1
                c[f"goal={'Y' if v in goal else 'N'} inj={'Y' if v in inj else 'N'} clean_env={'Y' if v in env else 'N'}"] += 1
for k in sorted(c):
    print(k, c[k])
