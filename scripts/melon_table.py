"""Amendment 4, section 6.2 table: MELON beside the other arms on the AgentDojo part of the delegation grid
(banking and slack, 20 tasks), conditions a, b, c, per suite, pooled over the models that have MELON cells.
usage: python3 scripts/melon_table.py  (from paper-tripwire/) -> paper_artifacts/tab/melon_e2x.tex + stdout"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json, sys
T = "."
ALL = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06", "qwen3-235b-a22b-instruct-2507"]
ARMS = [("none", "no defense"), ("rope", "ROPE (live)"), ("melon", "MELON"), ("tripwire_v2", "\\textbf{delegation (ours)}"),
        ("tripwire_strict_v2", "\\textbf{strict (ours)}")]


def cells(cond, model, arm, suite):
    out = []
    for f in glob.glob(f"{T}/data_v2/e2x_{cond}/{model}/{arm}/*/{suite}/*/e2x_{cond}/none.json"):
        d = json.load(open(f))
        if "utility" not in d or d.get("error"):
            sys.exit(f"unfinished or errored cell {f}")
        out.append(bool(d["utility"] if cond == "a" else d["security"]))
    return out


models = [m for m in ALL if glob.glob(f"{T}/data_v2/e2x_a/{m}/melon/*/*/*/e2x_a/none.json")]
rows = []
for arm, label in ARMS:
    vals = []
    for sn in ("banking", "slack"):
        for c in "abc":
            v = [x for m in models for x in cells(c, m, arm, sn)]
            vals.append(f"{sum(v)}/{len(v)}")
    rows.append(f"{label} & " + " & ".join(vals) + " \\\\")
    print(f"{arm:20}", vals)
hdr = ("\\begin{tabular}{@{}lcccccc@{}}\n\\toprule\n & \\multicolumn{3}{c}{banking} & \\multicolumn{3}{c}{slack} \\\\\n"
       "\\cmidrule(lr){2-4}\\cmidrule(l){5-7}\nConfiguration & a $\\uparrow$ & b $\\downarrow$ & c $\\downarrow$ & a $\\uparrow$ & b $\\downarrow$ & c $\\downarrow$ \\\\\n\\midrule\n")
open(f"{T}/paper_artifacts/tab/melon_e2x.tex", "w").write(hdr + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
print("models:", models)
