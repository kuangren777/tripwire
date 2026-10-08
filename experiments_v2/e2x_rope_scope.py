"""af-man #811: cross-tabulate the rope arm's admit/block in E2X conditions a and b against the live router's
cached scope for each task's prompt. The cache key is sha256(model || system || user) (common/llm_cache.py);
we rebuild system and user exactly as rope.router.route_and_scope does (_SCOPE_SYSTEM + fewshot, SENSITIVE TOOLS
block + trusted facts + TASK) and read the cached response. Pure lookup, no model call.
Marker for the task's (tool, arg): the override spec if present (FREE / RECORD / CONST / PROMPT ...), else
BUCKET(action-open) when the bucket is action-open, else 'floor' (the audited default applies).
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 e2x_rope_scope.py -> data/e2x/rope_scope_xtab.json"""
import collections, glob, hashlib, json, re, sys

sys.path.insert(0, "../ext/rope/src")
from rope import router as RT
from rope.fewshot import fewshot, trusted_facts
from rope.scopes_io import load_floor

T = "."
MODEL = "claude-opus-4-8"
cache = json.load(open(f"{T}/data/e2x/router_cache.json"))


def cached_scope(prompt, suite):
    floor = load_floor(suite)
    system = RT._SCOPE_SYSTEM + (("\n\nWORKED EXAMPLES:\n" + fewshot(suite)) if fewshot(suite) else "")
    tool_lines = [f"  {t}: {', '.join(a.keys())}" for t, a in floor.items()]
    tf = trusted_facts(suite)
    facts = f"TRUSTED ACCOUNT FACTS:\n{tf}\n\n" if tf else ""
    user = "SENSITIVE TOOLS (tool: sensitive parameters):\n" + "\n".join(tool_lines) + f"\n\n{facts}TASK: {prompt}"
    h = hashlib.sha256()
    for part in (MODEL, system, user):
        h.update(part.encode()); h.update(b"\0")
    e = cache.get(h.hexdigest())
    if not e:
        return None, "no-cache-entry"
    m = re.search(r"\{.*\}", e["response"], re.S)
    try:
        return json.loads(m.group(0)), "ok"
    except ValueError:
        return None, "unparseable"


def marker(d, tool, arg, floor):
    if not d:
        return "none"
    if tool not in floor or arg not in floor[tool]:
        return "unguarded"   # the audited floor does not list this parameter at all
    spec = (d.get("overrides") or {}).get(tool) or {}
    if arg in spec:
        return str(spec[arg]).split(":")[0].strip('"\\ ')
    return "BUCKET(action-open)" if d.get("bucket") == "action-open" else "floor"


rows = json.load(open(f"{T}/data/e2x/tasks.json"))
xtab = collections.defaultdict(collections.Counter)
suspects, scope_dump = [], {}
for r in rows:
    sc, st = cached_scope(r["prompt"], r["suite"])
    mk = marker(sc, r["tool"], r["arg"], load_floor(r["suite"]))
    scope_dump[r["id"]] = {"suite": r["suite"], "status": st, "bucket": (sc or {}).get("bucket"),
                           "named_source": (sc or {}).get("named_source"), "marker": mk}
    for cond in ("a", "b"):
        for f in glob.glob(f"{T}/data/e2x_{cond}/*/rope/*/*/{r['id']}/e2x_{cond}/none.json"):
            d = json.load(open(f))
            if "utility" not in d:
                continue
            passed = bool(d["security"] if cond == "b" else d["utility"])
            xtab[(cond, mk)]["admit" if passed else "block"] += 1
            xtab[(cond, r["suite"], mk)]["admit" if passed else "block"] += 1
            if passed and mk in ("floor", "RECORD", "CONST", "PROMPT"):   # floor here = guarded, no override
                suspects.append({"cond": cond, "task": r["id"], "suite": r["suite"], "marker": mk})
for k in sorted(xtab):
    if len(k) == 2:
        print(k, dict(xtab[k]))
print("scope statuses:", collections.Counter(v["status"] for v in scope_dump.values()))
print("suspect admissions:", suspects if suspects else "none")
json.dump({"xtab": {str(k): dict(v) for k, v in xtab.items()}, "scopes": scope_dump, "suspects": suspects},
          open(f"{T}/data/e2x/rope_scope_xtab.json", "w"), indent=1)
