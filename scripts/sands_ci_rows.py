"""S&S copy only: render the interval rows of tab/h1_permodel.tex and tab/v21.tex in
paper-overleaf (Overleaf 6ac0f249) as "lower to upper" instead of a bracketed pair. Values come from the exact
fractions in data_v2/provenance/compare.json (scripts/tables_from_raw.py, full precision), rounded once with fmtnum.
The script asserts that every rounded bound equals the number in the existing bracketed cell, so only the format
changes. The USENIX copy (paper-overleaf-v2) and its generators are not touched.
usage: python3 scripts/sands_ci_rows.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import json
import re
import sys
from fractions import Fraction
from pathlib import Path

T = Path(".")
TAB = T / "paper_artifacts" / "tab"
sys.path.insert(0, "scripts")
from fmtnum import fmt  # noqa: E402  one ROUND_HALF_UP at render time

full = json.load(open(T / "data_v2/provenance/compare.json"))["full_precision"]


def num(v):
    x = float(Fraction(v)); return ("$-$" if x < 0 else "") + fmt(abs(x), 1)


def pair(ci):
    return f"{num(ci[0])} to {num(ci[1])}"


def old_numbers(row):
    return [float(s.replace("$-$", "-")) for s in re.findall(r"(?:\$-\$)?\d+\.\d", row)]


def rewrite(name, cells):
    p = TAB / f"{name}.tex"
    lines = p.read_text().split("\n")
    i = next(k for k, l in enumerate(lines) if l.startswith("95\\% CI"))
    old = lines[i]
    new = "95\\% CI, pp" + " & " + " & ".join(cells) + " \\\\"
    assert old_numbers(old) == old_numbers(new), (name, old, new)
    lines[i] = new
    p.write_text("\n".join(lines))
    print(f"{name}: {old}\n  -> {new}")


h1 = full["h1_corrected=True"]["bootstrap"]
rewrite("h1_permodel", ["", ""] + [f"{pair(h1[a]['sec_ci'])} / {pair(h1[a]['cu_ci'])}" for a in ("tripwire_v2", "tripwire_strict_v2")])
v = full["v21_corrected=True"]["bootstrap"]
rewrite("v21", ["", "", f"{pair(v['sec_ci'])} / {pair(v['cu_ci'])}"])
