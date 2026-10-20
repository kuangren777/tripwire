"""Amendment 4, section 6.1: rule attribution of the lost non-synthesis held-out cells. Read-only over logs.
Lost cell = rope completes, tripwire_strict_v2 does not, on a non-synthesis task (census label as in
h1_synthesis_split.py). For each lost cell:
  A  replay the same model's none-arm clean trace through v2b_strict (diag_h1_cu.classify, same loop as
     diag_h1_cu.replay but keeping full values) and take the FIRST block;
  B  the same replay over the strict arm's own clean trace (its blocked calls are classified, not executed);
  source of A's value: the earliest tool result in the trace that contains it, re-run with the same arguments
     on the task environment with a unique marker in every injection vector. Marker in output: WRITABLE, else
     PROTECTED. LABEL:NONE (value in no tool result): NO_SOURCE. The test is per tool result, not per field.
usage: python3 scripts/h1_rule_attribution.py  (from paper-tripwire/) -> data_v2/diag/h1_rule_attribution.json
amendment 5: --arm-key v21_strict --trace-arm tripwire_strict_v21 [--models m1,m2] --out <json> replays with v2.1."""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, sys
from ast import literal_eval

sys.dont_write_bytecode = True
T = "."
sys.path.insert(1, T)
sys.path.insert(1, f"{T}/scripts")
for p in ("ext/rope/autodojo/src", "ext/rope/src"):
    if p not in sys.path:
        sys.path.insert(1, p)

from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402

from diag_h1_cu import SUITES, classify  # noqa: E402
from h1_synthesis_split import MODELS, clean_cells, synthesis_tasks  # noqa: E402
from tripwire import _values  # noqa: E402
from tripwire_v2 import ARMS, TripWireV2  # noqa: E402

D = f"{T}/data_v2/v2_heldout"
OUT = f"{T}/data_v2/diag/h1_rule_attribution.json"
ARM_KEY, TRACE_ARM = "v2b_strict", "tripwire_strict_v2"


def _txt(c):
    if isinstance(c, list):
        return " ".join(str(b.get("content", "")) if isinstance(b, dict) else str(b) for b in c)
    return "" if c is None else str(c)


def _args(tc):
    args = dict(tc["args"] or {})
    for k, v in args.items():
        if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
            try:
                args[k] = literal_eval(v)
            except Exception:  # noqa: BLE001
                pass
    return args


def first_block(trace):
    """Replay through v2b_strict; return (rule, fn, arg, full value, tool messages seen before the block) or None."""
    suite = SUITES[trace["suite_name"]]
    env = suite.user_tasks[trace["user_task_id"]].init_environment(suite.load_and_inject_default_environment({}))
    rt = FunctionsRuntime(suite.tools)
    tw = TripWireV2(**dict(ARMS[ARM_KEY]))
    user = next(m for m in trace["messages"] if m["role"] == "user")
    tw.query(_txt(user["content"]), rt, env, [])
    seen = []
    for m in trace["messages"]:
        if m["role"] != "tool":
            continue
        fn, args = m["tool_call"]["function"], _args(m["tool_call"])
        rs = classify(tw, fn, args)
        if rs:
            rule, arg, _ = rs[0]
            if rule == "R2b":   # the copied argument that triggered the anchor rule
                val = next((str(x) for vv in args.values() for x in _values(vv)
                            if len(str(x).strip()) >= 3 and tw.prov.source(x) in ("FREE_TEXT", "AMBIGUOUS")), "")
            else:
                val = next((str(x) for x in _values(args.get(arg))), "")
            return {"rule": rule, "tool": fn, "arg": arg, "val": val}, seen
        tw.prov.note_args(args)
        res, err = rt.run_function(env, fn, args)
        if err is None:
            tw.prov.add_call_result(args, res)
        seen.append((fn, args, _txt(m["content"])))
    return None, seen


def source_class(trace, blk, seen):
    if blk["rule"] == "LABEL:NONE":
        return "NO_SOURCE", None
    v = blk["val"].lower().strip()
    if len(v) < 3:
        return "NO_VALUE", None
    hit = next(((fn, args) for fn, args, out in seen if v in out.lower()), None)
    if hit is None:
        return "NOT_FOUND", None
    suite = SUITES[trace["suite_name"]]
    marks = {k: f"@@MK{i}@@" for i, k in enumerate(suite.get_injection_vector_defaults())}
    env = suite.user_tasks[trace["user_task_id"]].init_environment(suite.load_and_inject_default_environment(marks))
    res, err = FunctionsRuntime(suite.tools).run_function(env, hit[0], hit[1])
    out = str(res) if err is None else ""
    return ("WRITABLE" if "@@MK" in out else "PROTECTED"), hit[0]


def trace_of(model, arm, suite, task):
    fs = glob.glob(f"{D}/{model}/{arm}/*/{suite}/{task}/none/none.json")
    assert len(fs) == 1, (model, arm, suite, task)
    return json.load(open(fs[0]))


def main():
    global ARM_KEY, TRACE_ARM, OUT
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm-key", default=ARM_KEY); ap.add_argument("--trace-arm", default=TRACE_ARM)
    ap.add_argument("--models", default=",".join(MODELS)); ap.add_argument("--out", default=OUT)
    a = ap.parse_args(); ARM_KEY, TRACE_ARM, OUT = a.arm_key, a.trace_arm, a.out
    models = a.models.split(",")
    SYN = set()
    for sn in SUITES:
        SYN |= {(sn, i) for i in synthesis_tasks(sn)[0]}
    rows, gained = [], 0
    for m in models:
        r, s = clean_cells(m, "rope"), clean_cells(m, TRACE_ARM)
        for key in sorted(r):
            if key in SYN:
                continue
            if s[key] and not r[key]:
                gained += 1
            if not (r[key] and not s[key]):
                continue
            ta = trace_of(m, "none", *key)
            a, seen = first_block(ta)
            b, _ = first_block(trace_of(m, TRACE_ARM, *key))
            src, src_tool = source_class(ta, a, seen) if a else ("NO_BLOCK", None)
            rows.append({"model": m, "suite": key[0], "task": key[1],
                         "A": a and {**a, "val": a["val"][:60]}, "B": b and {**b, "val": b["val"][:60]},
                         "source": src, "source_tool": src_tool})
    n = len(rows)
    ra = collections.Counter(x["A"]["rule"] if x["A"] else "NO_BLOCK" for x in rows)
    rb = collections.Counter(x["B"]["rule"] if x["B"] else "NO_BLOCK" for x in rows)
    sc = collections.Counter(x["source"] for x in rows)
    agree = sum((x["A"] or {}).get("rule") == (x["B"] or {}).get("rule") for x in rows)
    print(f"non-synthesis cells lost (rope yes, strict no): {n}; gained (strict yes, rope no): {gained}")
    print("attribution A (none-arm legitimate path, first strict block):")
    for k, c in ra.most_common():
        print(f"  {k:18} {c:3}  {100*c/n:5.1f}%")
    print("attribution B (strict arm's own path):")
    for k, c in rb.most_common():
        print(f"  {k:18} {c:3}  {100*c/n:5.1f}%")
    print(f"A/B rule agreement {agree}/{n}")
    print("source of A's blocked value:")
    for k, c in sc.most_common():
        print(f"  {k:12} {c:3}  {100*c/n:5.1f}%")
    denom = n - sc["NO_BLOCK"]
    W, N0, P = sc["WRITABLE"], sc["NO_SOURCE"], sc["PROTECTED"]
    print(f"decision inputs (NO_BLOCK excluded, denominator {denom}): W+N0 = {W + N0} ({100*(W+N0)/max(denom,1):.1f}%), "
          f"P = {P} ({100*P/max(denom,1):.1f}%), other {denom - W - N0 - P}")
    json.dump({"n_lost": n, "n_gained": gained, "rule_A": ra, "rule_B": rb, "agree": agree, "source": sc,
               "rows": rows}, open(OUT, "w"), indent=1)


if __name__ == "__main__":
    main()
