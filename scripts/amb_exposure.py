"""Exposure of the ambiguity rule to false refusals on legitimate documents (read-only, no model calls).
The rule (tripwire.py Provenance.source) refuses a delegated value when the named document holds more than one
distinct value of the value's class (iban, email, url). We recompute, with the census's own document walk and
named-document match (e2x_prevalence.py) and tripwire.py's CLASSES and canon:
  (1) the 8 delegated destinations of the census: how many sit in a named document with >1 distinct same-class
      value, i.e. the rule would refuse the legitimate call;
  (2) every document the census walks (docs(env), six suites), and the subset named by some task prompt: how many
      hold >1 distinct value of at least one class.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 scripts/amb_exposure.py  (from paper-tripwire/)"""
import json, sys
sys.dont_write_bytecode = True
T = "."
sys.path.insert(1, T)
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from e2x_prevalence import docs, VERSION  # noqa: E402
from tripwire import CLASSES, canon, norm, value_class  # noqa: E402

prev = json.load(open(f"{T}/data/e2x/prevalence.json"))


def multi(text):
    t = norm(text)
    return {c: len({canon(x) for x in rx.findall(t)}) for c, rx in CLASSES.items()}


tot = dict(dest=0, amb=0, docs=0, docs_multi=0, named=0, named_multi=0)
for sn in ("banking", "slack", "travel", "shopping", "github", "dailylife"):
    suite = get_suite(VERSION, sn)
    env = suite.load_and_inject_default_environment({})
    D = docs(env)
    amb = 0
    for r in prev[sn]["rows"]:
        cls = value_class(canon(norm(r["value"])))
        d_hit = [k for k in D if k in r["doc"]]
        is_amb = bool(cls) and any(multi(D[k])[cls] > 1 for k in d_hit)
        amb += is_amb
        print(f"  {sn} {r['task']} {r['value']} class={cls} doc={r['doc']} ambiguous={is_amb}")
    named = set()
    for t in suite.user_tasks.values():
        p = t.PROMPT.lower()
        named |= {k for k in D if len(k) > 3 and (k.lower() in p or k.lower().removeprefix("www.") in p)}
    dm = [k for k, v in D.items() if any(n > 1 for n in multi(v).values())]
    nm = [k for k in named if k in dm]
    print(f"{sn:10} delegated dests {len(prev[sn]['rows'])} ambiguous {amb} | docs {len(D)} multi {len(dm)} | named docs {len(named)} multi {len(nm)}")
    tot["dest"] += len(prev[sn]["rows"]); tot["amb"] += amb; tot["docs"] += len(D); tot["docs_multi"] += len(dm)
    tot["named"] += len(named); tot["named_multi"] += len(nm)
print(tot)
