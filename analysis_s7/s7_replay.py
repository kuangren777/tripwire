"""S7 replay: walk a recorded trace through a TripWire v2 arm without a model call and record, for every call, the
labels and source-set memberships of its checked arguments and the arm's decision. Same logic as diag_h1_cu.replay,
extended to all six suites and to a caller-supplied environment (the grid documents).
Needs PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src (from paper-tripwire/)."""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import os, sys
from ast import literal_eval

T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, T)
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from diag_h1_cu import classify  # noqa: E402
from tripwire import CREDENTIAL_ARGS, TYPED_ONLY_ARGS, _values, canon, compact, norm  # noqa: E402
from tripwire_v2 import ARMS, CONTROL_ALL, READ_LOCATORS, TripWireV2  # noqa: E402

VERSION = "v1.2.2"
SUITE_NAMES = ("banking", "slack", "travel", "shopping", "github", "dailylife")
_SUITES = {}


def suite(name):
    if name not in _SUITES:
        _SUITES[name] = get_suite(VERSION, name)
    return _SUITES[name]


def checked_args(fn, args):
    """(argument, value) pairs the arm checks: control arguments, credential and typed-only arguments, read locators."""
    out = []
    for a, v in args.items():
        if a in CONTROL_ALL.get(fn, ()) or (fn, a) in CREDENTIAL_ARGS or (fn, a) in TYPED_ONLY_ARGS \
                or (fn in READ_LOCATORS and a in READ_LOCATORS[fn]):
            out += [(a, x) for x in _values(v)]
    return out


def membership(prov, value):
    """Every source set that holds the value, not only the first hit (tripwire.Provenance.source order)."""
    v, c = canon(norm(value)), compact(canon(norm(value)))
    k = prov.use_compact and len(c) >= 6
    s = set()
    if v and (v in prov.user or (k and c in prov.user_c)):
        s.add("user")
    if v and v in prov.struct:
        s.add("structured")
    if v and (any(v in f for f in prov.free) or (k and any(c in f for f in prov.free_c))):
        s.add("free")
    if v and v in prov.tainted:
        s.add("tainted")
    if v and (any(v in f for f in prov.deleg) or (k and any(c in f for f in prov.deleg_c))):
        s.add("delegated")
    return s


def user_text(trace):
    u = next(m for m in trace["messages"] if m["role"] == "user")
    c = u["content"]
    return " ".join(b.get("content", "") for b in c) if isinstance(c, list) else str(c)


def replay(trace, arm, env=None):
    """Per call: {fn, args, checked: [(arg, value, label, members)], reasons}. Blocked calls are not executed."""
    s = suite(trace["suite_name"])
    if env is None:
        env = s.user_tasks[trace["user_task_id"]].init_environment(s.load_and_inject_default_environment(trace.get("injections") or {}))
    rt = FunctionsRuntime(s.tools)
    tw = TripWireV2(**ARMS[arm])
    tw.query(user_text(trace), rt, env, [])
    out = []
    for m in trace["messages"]:
        if m["role"] != "tool":
            continue
        tc = m["tool_call"]
        fn, args = tc["function"], dict(tc["args"] or {})
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
                try:
                    args[k] = literal_eval(v)
                except Exception:  # noqa: BLE001
                    pass
        chk = [(a, str(x), tw.prov.source(x), sorted(membership(tw.prov, x))) for a, x in checked_args(fn, args)]
        rs = classify(tw, fn, args)
        out.append({"fn": fn, "args": args, "checked": chk, "reasons": rs})
        if not rs:
            tw.prov.note_args(args)
            res, err = rt.run_function(env, fn, args)
            if err is None:
                tw.prov.add_call_result(args, res)
    return out
