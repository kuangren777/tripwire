"""Table of the rope sensitivity arms on the delegation grid with denominators (external review round 2, S3).
Rows: live, clamped, audit-fix, both. Columns: a completed / n, b executed attacker destinations / n.
Live and clamped cover all 120 cells; audit-fix and both cover the 20 slack cells of two models, and live is also
shown on exactly those 20 cells. Read-only. usage: python3 scripts/rope_sensitivity_table.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json
T = "."


def cells(c, arm):
    o = {}
    for f in glob.glob(f"{T}/data_v2/e2x_{c}/*/{arm}/*/*/*/e2x_{c}/none.json"):
        p = f.split("/")
        o[(p[-7], p[-3])] = bool(json.load(open(f))["utility" if c == "a" else "security"])
    return o


def frac(d, keys=None):
    ks = sorted(d) if keys is None else keys
    return f"{sum(d[k] for k in ks)}/{len(ks)}"


A = {arm: (cells("a", arm), cells("b", arm)) for arm in ("rope", "rope_clamp", "rope_auditfix", "rope_auditfix_clamp")}
sub = sorted(A["rope_auditfix"][0])
rows = [("live, all cells", frac(A["rope"][0]), frac(A["rope"][1])),
        ("clamped, all cells", frac(A["rope_clamp"][0]), frac(A["rope_clamp"][1])),
        ("live, audit-fix cells", frac(A["rope"][0], sub), frac(A["rope"][1], sub)),
        ("audit-fix", frac(A["rope_auditfix"][0]), frac(A["rope_auditfix"][1])),
        ("both", frac(A["rope_auditfix_clamp"][0]), frac(A["rope_auditfix_clamp"][1]))]
tex = ("\\begin{tabular}{@{}lcc@{}}\n\\toprule\nROPE configuration & a completed $\\uparrow$ & b executed $\\downarrow$ \\\\\n\\midrule\n"
       + "\n".join(f"{r} & {a} & {b} \\\\" for r, a, b in rows) + "\n\\bottomrule\n\\end{tabular}\n")
open(f"{T}/paper_artifacts/tab/rope_sensitivity.tex", "w").write(tex)
print(tex)
