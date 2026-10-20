"""Post-hoc (external review round 1): task-clustered bootstrap for H2a, delegation minus rope clean utility in condition a of
the delegation grid. A cluster is one constructed task with all its model cells. 10,000 resamples, seed 0. Read-only.
usage: python3 scripts/h2a_cluster_bootstrap.py  (from paper-tripwire/) -> data_v2/e2x/h2a_cluster_bootstrap.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, random
T = "."


def cells(arm):
    o = {}
    for f in glob.glob(f"{T}/data_v2/e2x_a/*/{arm}/*/*/*/e2x_a/none.json"):
        p = f.split("/")
        o[(p[-7], p[-3])] = bool(json.load(open(f))["utility"])
    return o


d, r = cells("tripwire_v2"), cells("rope")
keys = sorted(set(d) & set(r))
assert len(keys) == 120, len(keys)
by = collections.defaultdict(list)
for k in keys:
    by[k[1]].append(k)
tasks = sorted(by)
rng = random.Random(0)


def gap(ts):
    ks = [k for t in ts for k in by[t]]
    return 100 * (sum(d[k] for k in ks) - sum(r[k] for k in ks)) / len(ks)


g0 = gap(tasks)
bs = sorted(gap([tasks[rng.randrange(len(tasks))] for _ in tasks]) for _ in range(10_000))
out = {"gap_pp": round(g0, 1), "ci": [round(bs[250], 1), round(bs[9749], 1)], "tasks": len(tasks), "cells": len(keys)}
print(out)
json.dump(out, open(f"{T}/data_v2/e2x/h2a_cluster_bootstrap.json", "w"), indent=1)
