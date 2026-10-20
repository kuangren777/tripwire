"""H2a's registered test (exact one-sided McNemar on paired task-model cells, condition a) applied to the delegation
arm against the clamped rope arm. Read-only. usage: python3 scripts/h2a_clamp_mcnemar.py -> data_v2/e2x/h2a_clamp_mcnemar.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json
from math import comb
T = "."


def cells(arm):
    o = {}
    for f in glob.glob(f"{T}/data_v2/e2x_a/*/{arm}/*/*/*/e2x_a/none.json"):
        p = f.split("/")
        o[(p[-7], p[-3])] = bool(json.load(open(f))["utility"])
    return o


d, c = cells("tripwire_v2"), cells("rope_clamp")
ks = sorted(set(d) & set(c))
assert len(ks) == 120
b = sum(d[k] and not c[k] for k in ks); cc = sum(c[k] and not d[k] for k in ks)
p = sum(comb(b + cc, i) for i in range(b, b + cc + 1)) / 2 ** (b + cc)
out = {"cells": len(ks), "deleg_only": b, "clamp_only": cc, "p_one_sided": p}
print(out)
json.dump(out, open(f"{T}/data_v2/e2x/h2a_clamp_mcnemar.json", "w"), indent=1)
