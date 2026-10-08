"""Generate every table in paper-v2 as a .tex fragment under paper-v2/tab/. Numbers come only from the
result files; nothing is typed by hand. Rerun after any analysis change.
usage: python3 tables_v2.py"""
import glob, json

T = "."
OUT = f"{T}/paper-v2/tab"
e2x = json.load(open(f"{T}/data/e2x_summary.json"))
xtab = json.load(open(f"{T}/data/e2x/rope_scope_xtab.json"))
h1 = json.load(open(f"{T}/data/v2_heldout/decision.json"))
cu = json.load(open(f"{T}/data/diag/h1_cu.json"))
prev = json.load(open(f"{T}/data/e2x/prevalence.json"))
bprev = json.load(open(f"{T}/data/e2x/boundary_prevalence.json"))
MODELS = {"gpt-4o-mini-2024-07-18": "gpt-4o-mini", "gpt-4o-2024-08-06": "gpt-4o",
          "qwen3-235b-a22b-instruct-2507": "qwen3-235b"}
ARMS = [("none", "no defense"), ("rope", "ROPE (live)"), ("tripwire_v2", "deleg (ours)"),
        ("tripwire_strict_v2", "strict (ours)"), ("tripwire_hist_v2", "hist (ours)")]
CONDS = [("a", "a clean"), ("a_h", "a\\_h seeded"), ("b", "b inserted"), ("c", "c replaced"), ("c_h", "c\\h seeded")]


def pooled(cond, arm):
    x = n = 0
    for m, arms in e2x.get(cond, {}).items():
        if m.endswith("_vs_rope") or not isinstance(arms, dict):
            continue
        v = arms.get(arm)
        if v:
            x += v[0]; n += v[1]
    return x, n


def cell(x, n):
    return "--" if not n else f"{x}/{n}"


# T1: E2X main 5x5
rows = []
for a, an in ARMS:
    rows.append(an + " & " + " & ".join(cell(*pooled(c, a)) for c, _ in CONDS) + r" \\")
open(f"{OUT}/e2x_main.tex", "w").write(
    "\\begin{tabular}{@{}lccccc@{}}\n\\toprule\nArm & a & a\\_h & b & c & c\\_h \\\\\n\\midrule\n"
    + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

# T2: rope on E2X by scope/suite marker (conditions a and b)
lines = []
for k, v in sorted(xtab["xtab"].items()):
    pass
mk = {}
for k, v in xtab["xtab"].items():
    key = [x.strip("' \"") for x in k.strip("()").split(", ")]
    if len(key) == 3 and key[0] in ("a", "b"):
        agg = mk.setdefault((key[0], key[2]), {"admit": 0, "block": 0})
        for k2 in ("admit", "block"):
            agg[k2] += v.get(k2, 0)
rows = []
for m in ("FREE", "RECORD", "floor", "unguarded"):
    ra = mk.get(("a", m), {}); rb = mk.get(("b", m), {})
    rows.append(f"{m} & {ra.get('admit',0)}/{ra.get('admit',0)+ra.get('block',0)} & "
                f"{rb.get('admit',0)}/{rb.get('admit',0)+rb.get('block',0)} \\\\")
open(f"{OUT}/rope_scope.tex", "w").write(
    "\\begin{tabular}{@{}lcc@{}}\n\\toprule\nRouter or audit verdict & a admitted & b admitted \\\\\n\\midrule\n"
    + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

# T3: H1 per-model ASR/CU
rows = []
for m, short in MODELS.items():
    r = [h1["per_model"][m][a] for a in ("none", "rope", "tripwire_v2", "tripwire_strict_v2")]
    rows.append(short + " & " + " & ".join(
        f"{100*v['ASR']/max(1,v['n_att']):.1f} / {100*v['CU']/max(1,v['n_clean']):.1f}" for v in r) + r" \\")
open(f"{OUT}/h1_permodel.tex", "w").write(
    "\\begin{tabular}{@{}lcccc@{}}\n\\toprule\nModel & none & rope & deleg & strict \\\\\n\\midrule\n"
    + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

# T4: H1 blocked-call classification
rows = []
labels = {"LABEL:NONE": "model-made value", "R1": "read locator", "LABEL:FREE_TEXT": "copied prose",
          "R2b": "unanchored write", "LABEL:DELEGATED": "delegated value", "LABEL:AMBIGUOUS": "ambiguous"}
for rule, lab in labels.items():
    v = cu["v2b_strict"]["table"].get("shopping|" + rule, 0) + cu["v2b_strict"]["table"].get("github|" + rule, 0) \
        + cu["v2b_strict"]["table"].get("dailylife|" + rule, 0)
    rows.append(f"{lab} & {v} \\\\")
open(f"{OUT}/h1_blocks.tex", "w").write(
    "\\begin{tabular}{@{}lr@{}}\n\\toprule\nTriggering rule & blocked calls \\\\\n\\midrule\n"
    + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")

# T5: boundary census
rows = []
for s in ("banking", "slack", "travel", "shopping", "github", "dailylife"):
    d = prev[s]; b = bprev[s]
    rows.append(f"{s} & {d['side_effect_destinations']} & {d['delegated']} & {b['must_synthesize']} & "
                f"{'yes' if b['reception_channel'] else 'no'} \\\\")
open(f"{OUT}/census.tex", "w").write(
    "\\begin{tabular}{@{}lcccl@{}}\n\\toprule\nSuite & destinations & delegated & must synthesize & reception \\\\\n\\midrule\n"
    + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}\n")
print("tables written to", OUT)
