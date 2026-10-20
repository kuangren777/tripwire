"""Shared helpers for the S7 checks: Wilson interval, task-cluster bootstrap."""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import math, random


def wilson(k, n, z=1.96):
    if not n:
        return [0.0, 1.0]
    p = k / n
    c = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    m = (p + z * z / (2 * n)) / (1 + z * z / n)
    return [max(0.0, m - c), min(1.0, m + c)]


def cluster_boot(rows, stat, cluster, n_boot=10000, seed=0):
    """95% percentile interval of stat over resamples of whole clusters (rows sharing rows[i][cluster])."""
    groups = {}
    for r in rows:
        groups.setdefault(r[cluster], []).append(r)
    keys = sorted(groups)
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        S = [r for k in (rng.choice(keys) for _ in keys) for r in groups[k]]
        vals.append(stat(S))
    vals.sort()
    return [vals[int(0.025 * n_boot)], vals[int(0.975 * n_boot) - 1]]
