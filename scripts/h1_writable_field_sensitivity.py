"""Exploratory sensitivity (not pre-registered): for WRITABLE cells of 6.1, is the blocked value itself inside an
injection slot? Re-run the source call with markers; if the value disappears from the output, the injection
vector overwrote the field holding it (value in an attacker-writable field). If it is still present, the value sits
in a field the attacker does not write, beside a field the attacker does."""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import json, sys, glob
T="."; sys.path.insert(1,T); sys.path.insert(1,T+"/scripts")
from h1_rule_attribution import first_block, trace_of, SUITES
from agentdojo.functions_runtime import FunctionsRuntime
d=json.load(open(T+"/data_v2/diag/h1_rule_attribution.json"))
res={"value_in_slot":0,"value_beside_slot":0}
for r in d["rows"]:
    if r["source"]!="WRITABLE": continue
    tr=trace_of(r["model"],"none",r["suite"],r["task"]); a,seen=first_block(tr)
    v=a["val"].lower(); fn,args=next((f,ar) for f,ar,out in seen if v in out.lower())
    s=SUITES[r["suite"]]; marks={k:f"@@MK{i}@@" for i,k in enumerate(s.get_injection_vector_defaults())}
    env=s.user_tasks[r["task"]].init_environment(s.load_and_inject_default_environment(marks))
    out,err=FunctionsRuntime(s.tools).run_function(env,fn,args); out=str(out).lower()
    k="value_beside_slot" if v in out else "value_in_slot"; res[k]+=1
    print(k, r["suite"], r["task"], r["model"][:10], fn, repr(v[:40]))
print(res)
