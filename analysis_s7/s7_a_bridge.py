"""S7 check a (AMENDMENT_s7.md): does the recorded condition-c trajectory equal the condition-a trajectory after the
global renaming v -> v'? Read-only over data_v2/e2x_a and data_v2/e2x_c, no model call.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 analysis/s7_a_bridge.py  (from paper-tripwire/) -> data_v2/s7/a_bridge.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import json, os, random, re, sys
from statistics import mean

T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(T, "analysis"))
sys.path.insert(1, T)
from s7_common import wilson, cluster_boot  # noqa: E402

MODELS = ["gpt-4o-2024-08-06", "gpt-4o-mini-2024-07-18", "qwen3-235b-a22b-instruct-2507"]
CONFIGS = ["none", "tripwire_v2", "rope"]
ROWS = {r["id"]: r for r in json.load(open(os.path.join(T, "data_v2/e2x/tasks.json")))}


def cell(cond, model, cfg, row):
    f = os.path.join(T, f"data_v2/e2x_{cond}", model, cfg, f"{model}-{cfg}", row["suite"], row["id"], f"e2x_{cond}", "none.json")
    return json.load(open(f)) if os.path.exists(f) else None


def text(c):
    if isinstance(c, list):
        return "".join(b.get("content") or "" for b in c if isinstance(b, dict))
    return c or ""


def traj(d):
    """Ordered tool calls (function, arguments) and tool-result strings; ids and final assistant text dropped."""
    calls, results = [], []
    for m in d["messages"]:
        if m["role"] == "assistant":
            for tc in m.get("tool_calls") or []:
                calls.append([tc["function"], tc.get("args") or {}])
        elif m["role"] == "tool":
            results.append(text(m.get("content")))
    return calls, results


def rename(obj, v, v2):
    rx = re.compile(re.escape(v), re.I)
    if isinstance(obj, str):
        return rx.sub(v2, obj)
    if isinstance(obj, list):
        return [rename(x, v, v2) for x in obj]
    if isinstance(obj, dict):
        return {k: rename(x, v, v2) for k, x in obj.items()}
    return obj


def key(obj):
    return json.dumps(obj, sort_keys=True, default=str).lower()


def divergence(ca, cc):
    for x, y in zip(ca, cc):
        if x[0] != y[0]:
            return "function"
        if key(x) != key(y):
            return "arguments"
    return "length"


def control_key(calls):
    """Function sequence plus checked-argument values (canonical form), the part a provenance-only defense labels."""
    from s7_replay import checked_args
    from tripwire import canon, norm
    return key([[fn, sorted([a, canon(norm(x))] for a, x in checked_args(fn, args))] for fn, args in calls])


def decisions(d, row, cond, arm):
    from e_rope_e2x import env_with_doc
    from s7_replay import replay, suite
    env = env_with_doc(suite(row["suite"]), row, row[f"text_{cond}"])
    return [[c["fn"], sorted({r for r, _, _ in c["reasons"]}), [lab for _, _, lab, _ in c["checked"]]] for c in replay(d, arm, env)]


def main():
    out = {}
    for cfg in CONFIGS:
        rows = []
        for model in MODELS:
            for tid, row in ROWS.items():
                a, c = cell("a", model, cfg, row), cell("c", model, cfg, row)
                if a is None or c is None or "utility" not in a or "security" not in c:
                    continue
                ca, ra = traj(a)
                cc, rc = traj(c)
                ca, ra = rename(ca, row["dest"], row["attacker"]), rename(ra, row["dest"], row["attacker"])
                call_eq = key(ca) == key(cc)
                # post hoc (added after the first run, see S7_RESULTS.md): control-argument and decision agreement
                ctl_eq = control_key(ca) == control_key(cc)
                dec = {arm: key(decisions(a, row, "a", arm)) == key(decisions(c, row, "c", arm)) for arm in ("v2b_deleg", "v2b_strict")}
                rows.append({"ctl_eq": ctl_eq, "dec_deleg_eq": dec["v2b_deleg"], "dec_strict_eq": dec["v2b_strict"],"model": model, "task": tid, "call_eq": call_eq, "full_eq": call_eq and key(ra) == key(rc),
                             "out_eq": bool(a["utility"]) == bool(c["security"]),
                             "div": None if call_eq else divergence(ca, cc)})
        res = {"cells": len(rows), "per_model": {}}
        for model in MODELS + ["pooled"]:
            R = [r for r in rows if model == "pooled" or r["model"] == model]
            if not R:
                continue
            e = {}
            for m in ("call_eq", "full_eq", "out_eq", "ctl_eq", "dec_deleg_eq", "dec_strict_eq"):
                k = sum(r[m] for r in R)
                e[m] = {"k": k, "n": len(R), "pct": round(100 * k / len(R), 1), "wilson": [round(100 * x, 1) for x in wilson(k, len(R))]}
                if model == "pooled":
                    e[m]["cluster_boot"] = [round(100 * x, 1) for x in cluster_boot(R, lambda S, m=m: mean(r[m] for r in S), "task")]
            e["divergence"] = {t: sum(r["div"] == t for r in R) for t in ("function", "arguments", "length")}
            res["per_model"][model] = e
        res["rows"] = rows
        out[cfg] = res
    os.makedirs(os.path.join(T, "data_v2/s7"), exist_ok=True)
    json.dump(out, open(os.path.join(T, "data_v2/s7/a_bridge.json"), "w"), indent=1)
    for cfg, res in out.items():
        print(f"== {cfg}: {res['cells']} cells")
        for model, e in res["per_model"].items():
            print(f"  {model:32s} call {e['call_eq']['k']}/{e['call_eq']['n']} full {e['full_eq']['k']} outcome {e['out_eq']['k']} ctl {e['ctl_eq']['k']} dec_deleg {e['dec_deleg_eq']['k']} dec_strict {e['dec_strict_eq']['k']} div {e['divergence']}"
                  + (f" boot call {e['call_eq']['cluster_boot']}" if "cluster_boot" in e["call_eq"] else ""))


if __name__ == "__main__":
    main()
