"""Post-hoc, $0 (no model calls): for each held-out synthesis cell that ROPE completes and the strict arm does not, print the
ROPE rule that applies to each synthesized ground-truth control value: the audited floor marker and the per-task override
of the cached opus scope. compile_policy uses floor + overrides only (the bucket is logged, never used); tools outside the
floor are always allowed. usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/h1_synthesis_rope_rule.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import sys
sys.path[:0]=["./scripts","."]
import h1_synthesis_split as H
from agentdojo.task_suite.load_suites import get_suite
from boundary_prevalence import VERSION, CONTROL_ALL, env_text
from rope.scopes_io import load_router_scopes
from rope.markers import marker_to_str
rows=[]
for sn in H.SUITES:
    syn,_,_,_=H.synthesis_tasks(sn)
    floor,scopes=load_router_scopes("opus",sn)
    suite=get_suite(VERSION,sn); env=suite.load_and_inject_default_environment({}); E=env_text(env)
    for m in H.MODELS:
        r=H.clean_cells(m,"rope"); s=H.clean_cells(m,"tripwire_strict_v2")
        for uid in sorted(syn):
            if r.get((sn,uid)) and not s.get((sn,uid)):
                t=suite.user_tasks[uid]; sc=scopes.get(t.PROMPT)
                gt=t.ground_truth(env); info=[]
                for c in gt:
                    for a in CONTROL_ALL.get(c.function,()):
                        v=c.args.get(a)
                        for x in (v if isinstance(v,(list,tuple)) else [v]):
                            x=str(x)
                            if len(x)>=3 and x.lower() not in t.PROMPT.lower() and x.lower() not in E:
                                ov=sc.overrides.get(c.function,{}).get(a) if sc else None
                                fl=floor.get(c.function,{}).get(a)
                                info.append(f"{c.function}.{a} floor={marker_to_str(fl) if fl else None} override={marker_to_str(ov) if ov else None}")
                print(m[:12],sn,uid,"|",sc.bucket if sc else None,"|","; ".join(info))
