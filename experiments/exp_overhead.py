"""RQ2 overhead micro-benchmark, no LLM involved.

Replays AgentDojo's scripted ground-truth solution of every user task (with the default
injections placed) through a plain ToolsExecutor and through TripWireExecutor, and times the
executor step. Reports added milliseconds per tool call and per task.
"""
import os
import json, os, statistics as st, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testbed"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tripwire"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import suite, default_injection, injection_candidates
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.functions_runtime import FunctionsRuntime, FunctionCall
from tripwire import TripWireExecutor

REPS = 20
out = []
for sname in ["banking", "slack", "travel", "workspace"]:
    S = suite(sname)
    it0 = sorted(S.injection_tasks)[0]
    for ut_id, ut in S.user_tasks.items():
        vecs = injection_candidates(sname, ut_id)
        for ex_name in ("plain", "tripwire"):
            ts, ncalls = [], 0
            for _ in range(REPS):
                env = S.load_and_inject_default_environment({v: default_injection(sname, it0) for v in vecs})
                env = ut.init_environment(env)
                calls = ut.ground_truth(env.model_copy(deep=True))
                rt = FunctionsRuntime(S.tools)
                ex = ToolsExecutor() if ex_name == "plain" else TripWireExecutor(mode="block")
                msgs = [{"role": "user", "content": ut.PROMPT}]
                if ex_name == "tripwire":
                    ex.query(ut.PROMPT, rt, env, [], {})
                t = 0.0
                for i, c in enumerate(calls):
                    m = {"role": "assistant", "content": None,
                         "tool_calls": [FunctionCall(function=c.function, args=dict(c.args), id=f"c{i}")]}
                    t0 = time.perf_counter()
                    _, _, env, msgs, _ = ex.query(ut.PROMPT, rt, env, [*msgs, m], {})
                    t += time.perf_counter() - t0
                ts.append(t)
                ncalls = len(calls)
            out.append({"suite": sname, "ut": ut_id, "ex": ex_name, "calls": ncalls, "sec_med": st.median(ts)})
json.dump(out, open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tw_overhead.json"), "w"), indent=0)
by = {}
for r in out:
    by.setdefault(r["ex"], []).append(r)
pl = {(r["suite"], r["ut"]): r for r in by["plain"]}
add_task = [r["sec_med"] - pl[(r["suite"], r["ut"])]["sec_med"] for r in by["tripwire"]]
add_call = [a / max(1, r["calls"]) for a, r in zip(add_task, by["tripwire"])]
print("tasks", len(add_task), "calls", sum(r["calls"] for r in by["tripwire"]))
print("added ms per task median %.3f p95 %.3f max %.3f" % (1000 * st.median(add_task),
      1000 * sorted(add_task)[int(.95 * len(add_task))], 1000 * max(add_task)))
print("added ms per call median %.3f p95 %.3f" % (1000 * st.median(add_call), 1000 * sorted(add_call)[int(.95 * len(add_call))]))
