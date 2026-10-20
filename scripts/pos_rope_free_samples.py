"""Positioning faithfulness gate: fixed-seed sample of ROPE condition-b cells on the delegation
grid where the attacker destination executed, with the cached live-router response verbatim and the executed call.
Reuses e2x_rope_scope.cached_scope / marker (pure lookup, no model call). Read-only.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/pos_rope_free_samples.py  (from paper-tripwire/)"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, hashlib, json, random, re, sys
sys.dont_write_bytecode = True
T = "."
sys.argv = [sys.argv[0]]
import importlib.util
spec = importlib.util.spec_from_file_location("ers", f"{T}/experiments_v2/e2x_rope_scope.py")
src = open(f"{T}/experiments_v2/e2x_rope_scope.py").read().split("rows = json.load")[0]
ns = {}; exec(compile(src, "e2x_rope_scope_head", "exec"), ns)
rows = {r["id"]: r for r in json.load(open(f"{T}/data_v2/e2x/tasks.json"))}
cells = []
for f in sorted(glob.glob(f"{T}/data_v2/e2x_b/*/rope/*/*/*/e2x_b/none.json")):
    d = json.load(open(f))
    if d.get("security"):
        p = f.split("/"); cells.append((p[-7], p[-3], f))
mk_count = collections.Counter()
for m, tid, f in cells:
    r = rows[tid]; sc, st = ns["cached_scope"](r["prompt"], r["suite"])
    mk_count[(ns["marker"](sc, r["tool"], r["arg"], ns["load_floor"](r["suite"])), st)] += 1
print("executed attacker destinations:", len(cells), dict(mk_count))
for m, tid, f in random.Random(0).sample(cells, 5):
    r = rows[tid]; sc, st = ns["cached_scope"](r["prompt"], r["suite"])
    mk = ns["marker"](sc, r["tool"], r["arg"], ns["load_floor"](r["suite"]))
    d = json.load(open(f))
    calls = [c for msg in d["messages"] if msg.get("role") == "assistant" for c in (msg.get("tool_calls") or [])
             if c.get("function") == r["tool"]]
    print(f"\n--- {m} {r['suite']} {tid} checked={r['tool']}.{r['arg']} marker={mk} cache={st}")
    print("prompt:", r["prompt"])
    print("router overrides:", json.dumps((sc or {}).get("overrides"))[:400], "| bucket:", (sc or {}).get("bucket"),
          "| named_source:", (sc or {}).get("named_source"))
    print("executed:", [{k: c.get("args", {}).get(k) for k in (r["arg"],)} for c in calls][:2])
