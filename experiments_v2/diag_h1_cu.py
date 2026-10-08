"""H1 utility-collapse diagnosis (af-man #1039). Held-out result diagnosis only: no method change, no retuning.
Replays the clean (attack=none) `none`-arm traces of the three held-out models through v2b_strict and v2b_deleg,
and for every call the arm would block records suite, tool, argument and the TRIGGERING RULE:
  R1            read locator not USER/TYPED (strict: not USER/STRUCTURED)
  R2b           no USER-anchored argument and some argument copied from tool text
  LABEL:x       the value's first-hit label x is in the mode's deny set (FREE_TEXT, AMBIGUOUS, DELEGATED, NONE)
  TRUST:x       credential/typed-only argument below its level
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 diag_h1_cu.py -> data/diag/h1_cu.json + tables"""
import collections, glob, json, sys
from ast import literal_eval

sys.path.insert(1, ".")
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from tripwire import CONTROL_ARGS, CREDENTIAL_ARGS, TYPED_ONLY_ARGS, _values, norm  # noqa: E402
from tripwire_v2 import ARMS, HISTORY, READ_LOCATORS, SIDE_EFFECT, TripWireV2  # noqa: E402

D = "./data/v2_heldout"
SUITES = {n: get_suite("v1.2.2", n) for n in ("shopping", "github", "dailylife")}
MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06", "qwen3-235b-a22b-instruct-2507"]
OUT = "./data/diag/h1_cu.json"


def classify(tw, fn, args):
    """Mirror the real executor: label checks apply to CONTROL args only, R1 to read locators, R2b to writes."""
    from tripwire_v2 import CONTROL_ALL
    deny = {"strict": {"FREE_TEXT", "AMBIGUOUS", "DELEGATED", "NONE"},
            "nodeleg": {"FREE_TEXT", "AMBIGUOUS", "DELEGATED"},
            "block": {"FREE_TEXT", "AMBIGUOUS"}}[tw.mode]
    reasons = []
    for a, v in args.items():
        if a not in CONTROL_ALL.get(fn, ()) and (fn, a) not in CREDENTIAL_ARGS and (fn, a) not in TYPED_ONLY_ARGS \
                and not (fn in READ_LOCATORS and a in READ_LOCATORS[fn]):
            continue
        for x in _values(v):
            lab = tw.prov.source(x)
            if fn in READ_LOCATORS and a in READ_LOCATORS[fn] and tw.r1:
                ok = ("USER", "STRUCTURED") if tw.mode == "block" and not tw.r1_deleg else ("USER", "STRUCTURED", "DELEGATED")
                ok = ("USER", "STRUCTURED") if tw.mode != "block" else ok
                if lab not in ok:
                    reasons.append(("R1", a, str(x)[:50]))
            if (fn, a) in CREDENTIAL_ARGS and lab != "USER":
                reasons.append(("TRUST:cred", a, str(x)[:50]))
            if (fn, a) in TYPED_ONLY_ARGS and lab not in ("USER", "STRUCTURED"):
                reasons.append(("TRUST:typed", a, str(x)[:50]))
            if lab in deny:
                reasons.append((f"LABEL:{lab}", a, str(x)[:50]))
    if tw.r2 and fn in SIDE_EFFECT and not reasons:
        anchored = any(len(str(x).strip()) >= 3 and tw.prov.source(x) == "USER" for vv in args.values() for x in _values(vv))
        copied = any(tw.prov.source(x) in ("FREE_TEXT", "AMBIGUOUS") for vv in args.values() for x in _values(vv)
                     if len(str(x).strip()) >= 3)
        if not anchored and copied:
            reasons.append(("R2b", "-", ""))
    return reasons


def replay(trace, arm_name):
    kw = dict(ARMS[arm_name])
    suite = SUITES[trace["suite_name"]]
    env = suite.user_tasks[trace["user_task_id"]].init_environment(suite.load_and_inject_default_environment({}))
    rt = FunctionsRuntime(suite.tools)
    tw = TripWireV2(**kw)
    user = next(m for m in trace["messages"] if m["role"] == "user")
    ut = " ".join(b.get("content", "") for b in user["content"]) if isinstance(user["content"], list) else str(user["content"])
    tw.query(ut, rt, env, [])
    blocks = []
    for m in trace["messages"]:
        if m["role"] != "tool":
            continue
        tc = m["tool_call"]; fn, args = tc["function"], dict(tc["args"] or {})
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
                try:
                    args[k] = literal_eval(v)
                except Exception:  # noqa: BLE001
                    pass
        rs = classify(tw, fn, args)
        if rs:
            blocks.append({"tool": fn, "rs": rs[:3]})
        else:
            tw.prov.note_args(args)
            res, err = rt.run_function(env, fn, args)
            if err is None:
                tw.prov.add_call_result(args, res)
    return blocks


def main():
    out = {}
    for arm in ("v2b_strict", "v2b_deleg"):
        tab = collections.Counter(); ex = collections.defaultdict(list); ntr = 0
        for model in MODELS:
            for f in glob.glob(f"{D}/{model}/none/*/*/user_task_*/none/none.json"):
                d = json.load(open(f))
                if "utility" not in d:
                    continue
                ntr += 1
                for b in replay(d, arm):
                    for r, a, v in b["rs"]:
                        key = (d["suite_name"], r)
                        tab[key] += 1
                        if len(ex[key]) < 2:
                            ex[key].append({"model": model, "task": d["user_task_id"], "tool": b["tool"], "arg": a, "val": v})
        out[arm] = {"n_traces": ntr, "table": {f"{s}|{r}": c for (s, r), c in sorted(tab.items())}, "examples": {f"{a}|{b}": v for (a, b), v in ex.items()}}
        print(f"== {arm} ({ntr} clean traces)")
        for (s, r), c in sorted(tab.items(), key=lambda kv: -kv[1]):
            print(f"  {s:10} {r:15} {c:4}")
    import os
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, "w"), indent=1)


if __name__ == "__main__":
    main()
