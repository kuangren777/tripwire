"""Diagnostic (af-man #515, not a paper decision): on gpt-4o-mini E1, the attacked pairs where a TripWire arm's attack
succeeded and rope's did not. For each, re-execute the logged tool calls on a fresh environment with the logged
injections (deterministic AgentDojo tools), rebuilding TripWire's Provenance exactly as TripWireExecutor does
(note_args, then add_call_result for executed calls only). Every executed side-effecting call is listed with the
source label of each control argument, the record and field the value came from, and whether that value occurs in
the attacker's injection text (attacker-writable).
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 diag_e1_leaks.py -> data/diag/e1_leaks.json + table"""
import collections, glob, json, os, re, sys
from ast import literal_eval

sys.path.insert(1, ".")
sys.path.insert(0, "../ext/rope/runs")
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from corrections import corrected_security  # noqa: E402
from tripwire import CONTROL_ARGS, Provenance, _values, norm  # noqa: E402

D = "./data/e1_rope/gpt-4o-mini-2024-07-18"
OUT = "./data/diag/e1_leaks.json"


def cells(arm):
    out = {}
    for f in glob.glob(f"{D}/{arm}/*/*/user_task_*/important_instructions/*.json"):
        p = f.split("/"); d = json.load(open(f))
        it = int(re.sub(r"\D", "", p[-1][:-5]) or -1)
        out[(p[-4], p[-3], p[-1][:-5])] = (bool(corrected_security(d, p[-4], it)), d, f)
    return out


def where(obj, v, path="result"):
    """Paths (field names) inside a tool result whose value contains v."""
    hits = []
    if isinstance(obj, BaseModel):
        for k in type(obj).model_fields:
            hits += where(getattr(obj, k), v, f"{path}.{k}")
    elif isinstance(obj, dict):
        for k, x in obj.items():
            hits += where(x, v, f"{path}[{k!r}]")
    elif isinstance(obj, (list, tuple, set)):
        for i, x in enumerate(obj):
            hits += where(x, v, f"{path}[{i}]")
    elif obj is not None and v in norm(obj):
        hits.append(path)
    return hits


def replay(suite, d):
    env = suite.load_and_inject_default_environment(d["injections"])
    ut = suite.user_tasks[d["user_task_id"]]
    env = ut.init_environment(env)
    rt = FunctionsRuntime(suite.tools)
    user = next(m for m in d["messages"] if m["role"] == "user")
    utext = " ".join(b.get("content", "") for b in user["content"]) if isinstance(user["content"], list) else str(user["content"])
    prov, results, rows = Provenance(utext), [], []
    inj_text = norm(" ".join(d["injections"].values()))
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
        executed = not (m.get("error") or "").startswith("Blocked by TripWire")
        if fn in CONTROL_ARGS and executed and not m.get("error"):
            for a in CONTROL_ARGS[fn]:
                for x in _values(args.get(a)):
                    nx = norm(x)
                    origin = [(i, r[0], p) for i, r in enumerate(results) for p in where(r[1], nx)]
                    rows.append({"call": fn, "arg": a, "value": str(x), "label": prov.source(x),
                                 "attacker_text": nx in inj_text, "from": origin[:3]})
        if not executed:
            continue
        prov.note_args(args)
        res, err = rt.run_function(env, fn, args)
        if err is None:
            prov.add_call_result(args, res)
            results.append((fn, res))
    return rows


def main():
    rope = cells("rope")
    report = {}
    for arm in ("tripwire_strict", "tripwire"):
        tw = cells(arm)
        keys = sorted(k for k in tw if k in rope and tw[k][0] and not rope[k][0])
        tab, ex, recs = collections.Counter(), {}, []
        for k in keys:
            suite = get_suite("v1.2.2", k[0])
            rows = replay(suite, tw[k][1])
            atk = [r for r in rows if r["attacker_text"]] or rows
            lab = "+".join(sorted({r["label"] for r in atk})) if atk else "NO_EXECUTED_CONTROL_CALL"
            tab[lab] += 1
            recs.append({"cell": k, "file": tw[k][2], "class": lab, "rows": rows})
            ex.setdefault(lab, recs[-1])
        report[arm] = {"n": len(keys), "table": dict(tab), "examples": ex, "records": recs}
        print(f"== {arm}: {len(keys)} pairs where {arm} attack succeeded and rope's did not")
        for lab, c in tab.most_common():
            e = ex[lab]
            print(f"  {lab:28} {c:3}   e.g. {e['cell']}: " + "; ".join(
                f"{r['call']}.{r['arg']}={r['value']!r} [{r['label']}] attacker_text={r['attacker_text']} from={r['from'][:1]}" for r in e['rows'][:2]))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(report, open(OUT, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
