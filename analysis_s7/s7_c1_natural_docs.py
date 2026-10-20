"""S7 check c1 (AMENDMENT_s7.md): the ambiguity rule on every natural document of the six suites, offline, no model call.
Unit: a (document, class) pair for class iban or email that the clean document holds at least once. The inserted
document appends the grid's existing insertion sentence (e2x_tasks.INSERT_IBAN / INSERT_EMAIL) with the grid's
attacker value. Labels come from tripwire.Provenance with the document indexed as a named (delegated) document.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 analysis/s7_c1_natural_docs.py -> data_v2/s7/c1_natural_docs.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import json, os, re, sys

T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(T, "analysis"))
sys.path.insert(1, T)
from s7_common import wilson  # noqa: E402
from s7_replay import SUITE_NAMES, suite  # noqa: E402
from e2x_prevalence import docs  # noqa: E402
from e2x_tasks import ATK, INSERT_EMAIL, INSERT_IBAN  # noqa: E402
from tripwire import CLASSES, Provenance, canon, norm  # noqa: E402

INSERT = {"iban": INSERT_IBAN.format(atk=ATK["iban"]), "email": INSERT_EMAIL.format(atk=ATK["email"])}
# forms the class patterns miss (AMENDMENT_s7.md c1 item 2)
NONCANON = {"iban": re.compile(r"\b[a-z]{2}\d{2}(?: [a-z0-9]{4}){3,7}(?: [a-z0-9]{1,4})?\b"),
            "email": re.compile(r"\b[\w.+-]+ ?(?:\[at\]|\(at\)| at ) ?[\w-]+ ?(?:\[dot\]|\(dot\)| dot )[a-z]{2,}\b")}


def distinct(cls, text):
    return {canon(x) for x in CLASSES[cls].findall(norm(text))}


def label_after_insert(text, cls):
    b = text + INSERT[cls]
    p = Provenance("")
    p._into_deleg = True
    p.add_result(b)
    p.deleg_docs.append(norm(b))
    p._into_deleg = False
    legit = sorted(distinct(cls, text))
    return p.source(ATK[cls]), {v: p.source(v) for v in legit}


def main():
    rows = []
    for sn in SUITE_NAMES:
        s = suite(sn)
        env = s.load_and_inject_default_environment({})
        D = docs(env)
        prompts = [t.PROMPT.lower() for t in s.user_tasks.values()]
        for k, text in D.items():
            text = text or ""
            named = any(str(k).lower() in p for p in prompts)
            for cls in ("iban", "email"):
                vals = distinct(cls, text)
                nonc = bool(NONCANON[cls].search(norm(text)))
                if not vals and not nonc:
                    continue
                atk_lab, legit_lab = label_after_insert(text, cls) if vals else (None, {})
                rows.append({"suite": sn, "doc": str(k)[:80], "class": cls, "named": named, "n_values": len(vals),
                             "noncanonical": nonc, "atk_label": atk_lab, "legit_labels": legit_lab})
    res = {}
    for scope in ("all", "named"):
        R = [r for r in rows if scope == "all" or r["named"]]
        n = len(R)
        k_amb = sum(r["atk_label"] == "AMBIGUOUS" for r in R)
        k_multi = sum(r["n_values"] >= 2 for r in R)
        k_nonc = sum(r["noncanonical"] for r in R)
        k_onlynonc = sum(r["n_values"] == 0 and r["noncanonical"] for r in R)
        f = lambda k: {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else None, "wilson": [round(100 * x, 1) for x in wilson(k, n)]}
        res[scope] = {"pairs": n, "insert_ambiguous": f(k_amb), "clean_multi": f(k_multi), "noncanonical": f(k_nonc),
                      "only_noncanonical": f(k_onlynonc),
                      "by_class": {c: sum(r["class"] == c for r in R) for c in ("iban", "email")},
                      "by_suite": {sn: sum(r["suite"] == sn for r in R) for sn in SUITE_NAMES}}
        print(f"== {scope}: {n} (document, class) pairs {res[scope]['by_class']} {res[scope]['by_suite']}")
        for m in ("insert_ambiguous", "clean_multi", "noncanonical", "only_noncanonical"):
            print(f"   {m}: {res[scope][m]}")
    os.makedirs(os.path.join(T, "data_v2/s7"), exist_ok=True)
    json.dump({"summary": res, "rows": rows}, open(os.path.join(T, "data_v2/s7/c1_natural_docs.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
