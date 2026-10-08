"""Dev-set offline proxy for TripWire v2 rules (af-man #524). Takes the undefended (`none`) E1 traces of a model,
re-executes each logged tool call on a fresh environment with the logged injections, and lets a TripWire arm
(tripwire_v2.ARMS) decide each call: a refused call is skipped, every other call runs as logged. Utility and security
are then re-scored with AgentDojo's own checks on the resulting environment.
This is a proxy: a live agent would react to a refusal. It is calibrated against the live v1 arm (arm `v1` here vs
E1 `tripwire`). Development data only; no model call.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 dev_replay.py [model ...] -> data/dev_v2/replay.json"""
import collections, glob, json, os, sys
from ast import literal_eval

sys.path.insert(1, ".")
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from tripwire_v2 import ARMS, TripWireV2  # noqa: E402

D = "./data/e1_rope"
OUT = "./data/dev_v2/replay.json"
SUITES = {n: get_suite("v1.2.2", n) for n in ("banking", "slack", "travel")}


def user_text(d):
    m = next(m for m in d["messages"] if m["role"] == "user")
    c = m["content"]
    return " ".join(b.get("content", "") for b in c) if isinstance(c, list) else str(c)


def replay(d, arm_kw):
    suite = SUITES[d["suite_name"]]
    if arm_kw and arm_kw.get("v2c"):
        from tripwire_v2 import HISTORY
        arm_kw = {**arm_kw, "history": HISTORY.get(d["suite_name"])}
    ut = suite.user_tasks[d["user_task_id"]]
    env = ut.init_environment(suite.load_and_inject_default_environment(d["injections"] or {}))
    pre = env.model_copy(deep=True)
    rt = FunctionsRuntime(suite.tools)
    tw = TripWireV2(**arm_kw)
    tw.query(user_text(d), rt, env, [])
    stack, blocked = [], 0
    for m in d["messages"]:
        if m["role"] != "tool":
            continue
        tc = m["tool_call"]; fn, args = tc["function"], dict(tc["args"] or {})
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
                try:
                    args[k] = literal_eval(v)
                except Exception:  # noqa: BLE001
                    pass
        if tw.check(fn, args) and tw.mode != "monitor":
            blocked += 1
            continue
        tw.prov.note_args(args)
        res, err = rt.run_function(env, fn, args)
        if err is None:
            tw.prov.add_call_result(args, res)
        stack.append(FunctionCall(function=fn, args=args))
    last = next((m for m in reversed(d["messages"]) if m["role"] == "assistant"), None)
    out = last["content"] if last and isinstance(last.get("content"), list) else []   # content blocks, as AgentDojo passes them
    util = suite._check_task_result(ut, out, pre, env, stack)
    sec = None
    if d.get("injection_task_id"):
        it = suite.get_injection_task_by_id(d["injection_task_id"])
        sec = suite._check_task_result(it, out, pre, env, stack)
    return util, sec, blocked


def main():
    only = os.environ.get("ARMS", "").split(",") if os.environ.get("ARMS") else None
    models = sys.argv[1:] or sorted(m for m in os.listdir(D) if not m.startswith("_"))
    res, rows = {}, []
    for model in models:
        files = glob.glob(f"{D}/{model}/none/*/*/user_task_*/*/*.json")
        traces = [json.load(open(f)) for f in files]
        traces = [d for d in traces if "utility" in d]
        res[model] = {}
        for arm, kw in {"none": None, **ARMS}.items():
            if only and arm not in only:
                continue
            c = collections.Counter()
            for d in traces:
                if kw is None:
                    u, s, b = bool(d["utility"]), (bool(d["security"]) if d.get("injection_task_id") else None), 0
                else:
                    try:
                        u, s, b = replay(d, kw)
                    except Exception as e:  # noqa: BLE001
                        c["replay_error"] += 1; continue
                if d.get("injection_task_id"):
                    c["n_att"] += 1; c["asr"] += bool(s); c["ua"] += bool(u)
                else:
                    c["n_clean"] += 1; c["cu"] += bool(u)
                c["blocked_calls"] += b
                rows.append({"model": model, "arm": arm, "suite": d["suite_name"], "ut": d["user_task_id"],
                             "it": d.get("injection_task_id"), "util": bool(u), "sec": s, "blocked": b})
            res[model][arm] = dict(c)
            print(f"{model:24} {arm:10} ASR {c['asr']}/{c['n_att']}  CU {c['cu']}/{c['n_clean']}  UA {c['ua']}/{c['n_att']}  "
                  f"blocked {c['blocked_calls']}  errors {c['replay_error']}", flush=True)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({"summary": res, "rows": rows}, open(OUT.replace(".json", f"_{'_'.join(models)}{'_' + '-'.join(only) if only else ''}.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
