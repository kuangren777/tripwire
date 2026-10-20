"""Prose numbers of the S&S paper, generated from raw logs and committed analysis outputs.
Every result number printed in the prose of paper_artifacts/sec/*.tex is a macro defined in paper_artifacts/tab/prose_numbers.tex,
written here with one fmtnum ROUND_HALF_UP on exact Fractions. Protocol constants (task counts per condition, margins,
resample counts, thresholds) stay literal and are listed in TABLE_PROVENANCE.md section 7.

V holds each macro's value. PHRASES holds (file, template) pairs. A template is a verbatim phrase of the tex in which
each number is written as <<Name>>.
  check (default): fill every template with the recomputed values and require the filled phrase to occur exactly once
         in its file. A phrase that is not found is printed as MISMATCH with the nearest tex phrase, and the run exits 1
         (errata discipline: stop and report, never overwrite silently).
  --apply: after a clean check, replace each filled phrase by the template with \\Name{} and write the macro file.
  --write: only rewrite tab/prose_numbers.tex.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/prose_numbers.py [--apply|--write]"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import contextlib, difflib, io, json, os, re, runpy, sys
from fractions import Fraction
from pathlib import Path

T = Path(".")
P = Path(os.environ.get("PN_PAPER", T / "paper_artifacts"))
sys.path[:0] = [str(T / "scripts"), str(T)]
import tables_from_raw as TR  # noqa: E402
from fmtnum import fmt  # noqa: E402

V, SRC, PHRASES = {}, {}, []


def v(name, value, src):
    """Register one macro value with a one-line source note (written as a comment in the macro file)."""
    s = value if isinstance(value, str) else str(value)
    if name in V and V[name] != s:
        raise SystemExit(f"macro {name} defined twice with {V[name]} and {s}")
    V[name] = s; SRC[name] = src


def ph(file, template):
    PHRASES.append((f"sec/{file}.tex", template))


def pc(x, n, nd=1):
    return fmt(Fraction(100 * x, n), nd)


def neg(x, nd=1):
    return ("$-$" if x < 0 else "") + fmt(abs(x), nd)


CACHE = os.environ.get("PN_CACHE")   # iteration only: a pickle dir; the committed run uses no cache


def cached(key, fn):
    import pickle
    if not CACHE:
        return fn()
    f = Path(CACHE) / f"{key}.pkl"
    if f.exists():
        return pickle.loads(f.read_bytes())
    r = fn(); Path(CACHE).mkdir(parents=True, exist_ok=True); f.write_bytes(pickle.dumps(r)); return r


def script(name, keys):
    """Selected globals of a committed analysis script run as __main__ (its printout is discarded)."""
    def run():
        with contextlib.redirect_stdout(io.StringIO()):
            old = sys.argv; sys.argv = [name]
            try:
                g = runpy.run_path(str(T / "scripts" / f"{name}.py"), run_name="__main__")
            finally:
                sys.argv = old
        return {k: g[k] for k in keys}
    return cached(f"script_{name}", run)


def J(rel):
    return json.load(open(T / rel))


def fill(t, macro=False):
    return re.sub(r"<<(\w+)>>", (lambda m: f"\\{m.group(1)}{{}}") if macro else (lambda m: V[m.group(1)]), t)


# ------------------------------------------------------------------ data
G = {c: TR.grid(c) for c in ("a", "a_h", "b", "c", "c_h", "m", "s", "ma")}
M3 = TR.M3
MINI, GPT4O, QWEN = M3
TASKS = {t["id"]: t for t in J("data_v2/e2x/tasks.json")}


def cnt(c, cfg, models=M3, suites=None):
    o = [x for (m, k, t), x in G[c].items() if k == cfg and m in models and (suites is None or TASKS[t]["suite"] in suites)]
    return sum(o), len(o)



WORDS = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 8: "eight", 10: "ten", 30: "thirty"}

# ================================================================== spec
# ---- delegation grid (RQ1, abstract, intro)
dA, nA = cnt("a", "tripwire_v2"); rA, _ = cnt("a", "rope"); dB, nB = cnt("b", "tripwire_v2"); rB, _ = cnt("b", "rope")
v("PNGridCells", nB, "grid cells per condition, data_v2/e2x_b over three models")
v("PNDelegB", dB, "delegation condition b executed attacker destinations, data_v2/e2x_b")
v("PNRopeB", rB, "ROPE (live) condition b executed attacker destinations, data_v2/e2x_b")
v("PNDelegAPct", pc(dA, nA), f"delegation condition a completion {dA}/{nA}, data_v2/e2x_a")
v("PNRopeAPct", pc(rA, nA), f"ROPE condition a completion {rA}/{nA}, data_v2/e2x_a")
v("PNDelegBPct", pc(dB, nB), f"delegation condition b {dB}/{nB}")
v("PNRopeBPct", pc(rB, nB), f"ROPE condition b {rB}/{nB}")
noneA = {(m, t): o for (m, k, t), o in G["a"].items() if k == "none"}
noneC = {(m, t): o for (m, k, t), o in G["c"].items() if k == "none"}
v("PNEquivMatch", sum(noneA[k] == noneC[k] for k in noneA), "no-defense cells with condition a utility == condition c attack")
summ = J("data_v2/e2x_summary.json")["a"]["tripwire_v2_vs_rope"]
mant, ex = f"{summ['p']:.1e}".split("e")
v("PNHTwoAP", f"{mant}\\times 10^{{{int(ex)}}}", "exact one-sided McNemar p, data_v2/e2x_summary.json a.tripwire_v2_vs_rope.p")
lau, nlau = cnt("c_h", "tripwire_strict_v2"); lauh, _ = cnt("c_h", "tripwire_hist_v2")
assert lau == lauh
v("PNLaunder", lau, "c-seeded executed attacker destinations, strict and hist each, data_v2/e2x_c_h")
v("PNSeededCells", nlau, "c-seeded cells per configuration")
ph("abstract", "admitted <<PNDelegB>> of <<PNGridCells>> constructed insertions that keep the legitimate value in canonical form and completed <<PNDelegAPct>>\\% of clean\ntasks, against <<PNRopeB>> and <<PNRopeAPct>>\\% for ROPE with its live router.")
ph("abstract", "in <<PNLaunder>> of <<PNSeededCells>> cells per configuration")
ph("intro", "admits <<PNDelegB>> of <<PNGridCells>> inserted destinations that keep the legitimate value in canonical form, against <<PNRopeB>> for ROPE with its live router. It also completes <<PNDelegAPct>>\\% of clean delegated\ntasks against <<PNRopeAPct>>\\% for ROPE")
ph("evaluation", "treats the <<PNGridCells>> task-model cells as independent pairs, gives $p=<<PNHTwoAP>>$")
ph("evaluation", "H2b holds, since <<PNDelegBPct>>\\% is below ROPE's <<PNRopeBPct>>\\% plus 2 pp.")
ph("evaluation", "<<PNEquivMatch>> of <<PNGridCells>> condition a utility cells equal")
ph("endmatter", "in <<PNLaunder>> of <<PNSeededCells>> cells for each of the strict and hist configurations")

# ---- adaptive insertion (RQ1)
O2 = [GPT4O, MINI]   # table order gpt-4o / gpt-4o-mini
mD, mN = cnt("m", "tripwire_v2", O2); mNone, _ = cnt("m", "none", O2); sD, _ = cnt("s", "tripwire_v2", O2)
mS, _ = cnt("m", "tripwire_strict_v2", O2); sS, _ = cnt("s", "tripwire_strict_v2", O2)
mR, _ = cnt("m", "rope", O2); sR, _ = cnt("s", "rope", O2)
shared = len({(m, t) for (m, k, t), o in G["m"].items() if k == "tripwire_v2" and o} &
             {(m, t) for (m, k, t), o in G["m"].items() if k == "none" and o})
assert mD == mNone, "RQ1 says delegation admits as many masked attacks as no defense executes"
assert mS == sS == 0
v("PNAdaptCells", mN, "adaptive cells per configuration, data_v2/e2x_{m,s}, gpt-4o + gpt-4o-mini")
v("PNMaskDeleg", mD, "masked: delegation executed attacker destinations (identical cell set to no defense)")
v("PNMaskShared", shared, "masked cells admitted under both delegation and no defense")
v("PNStruckDeleg", sD, "struck: delegation executed attacker destinations")
v("PNAdaptStrict", mS, "strict executed attacker destinations, masked and struck each")
v("PNMaskRope", mR, "masked: ROPE (live)"); v("PNStruckRope", sR, "struck: ROPE (live)")
for nm, cfg in (("Deleg", "tripwire_v2"), ("None", "none")):
    for mm, tag in ((GPT4O, "Four"), (MINI, "Mini")):
        x, n = cnt("ma", cfg, [mm]); v(f"PNMaCl{nm}{tag}", x, f"masked clean control {cfg} {mm}, data_v2/e2x_ma")
v("PNAdaptTasks", n, "tasks per model in the masked clean control")
ADA = {t["id"]: t for t in J("data_v2/e2x/tasks_adaptive.json")}
dec = 0
for f in (T / "data_v2/e2x_m").glob(f"{MINI}/tripwire_v2/*/slack/*/e2x_m/none.json"):
    d = json.load(open(f)); atk_ = ADA[f.parts[-3]]["attacker"]
    tried = [m for m in d["messages"] if m.get("role") == "tool" and atk_ in json.dumps((m.get("tool_call") or {}).get("args", {}))]
    if d.get("utility") and tried:
        assert all(m.get("error") for m in tried) and not d.get("security"); dec += 1
v("PNMaskSlackDecoded", dec, "masked slack cells, gpt-4o-mini delegation: legitimate invite executed, attacker invite refused with an error")
ph("evaluation", "the \\delegcfg{} admits <<PNMaskDeleg>> of <<PNAdaptCells>> attacker destinations, as many as the agent with no defense executes, with <<PNMaskShared>> cells in common.")
ph("evaluation", "the \\delegcfg{} admits <<PNStruckDeleg>> of <<PNAdaptCells>>, since")
ph("evaluation", "The \\strictcfg{} admits <<PNAdaptStrict>> of <<PNAdaptCells>> in both conditions")
ph("evaluation", "ROPE with its live router admits <<PNMaskRope>> and <<PNStruckRope>> of <<PNAdaptCells>>.")
ph("evaluation", "completes <<PNMaClDelegFour>> and <<PNMaClDelegMini>> of <<PNAdaptTasks>> against <<PNMaClNoneFour>> and <<PNMaClNoneMini>> with no defense")
ph("evaluation", "In <<PNMaskSlackDecoded>> masked slack cells")

# ---- transfer check on the benchmark's delegated prompts (RQ1)
import natural_transfer as NT  # noqa: E402
nrows, nres, nmiss = NT.load(); assert not nmiss
def nat(cond, arm, pred=lambda x: True):
    s_ = [x for x in nres if x["cond"] == cond and x["arm"] == arm and pred(x)]
    return sum(x["hit"] for x in s_), len(s_)
btasks = [r for r in nrows if r["text_b"]]
v("PNNatTasks", len(nrows), "delegated census prompts, data_v2/v2_natural/tasks.json")
v("PNNatBTasks", len(btasks), "prompts with an insertion template (text_b)")
v("PNNatBSlack", sum(r["suite"] == "slack" for r in btasks), "of those, slack tasks (one shared page)")
for nm, arm in (("None", "none"), ("Rope", "rope"), ("Deleg", "tripwire_v2"), ("Strict", "tripwire_strict_v2")):
    x, n = nat("b", arm); v(f"PNNat{nm}B", x, f"transfer b admitted, {arm}")
    y, na = nat("a", arm); v(f"PNNat{nm}A", y, f"transfer a completed, {arm}")
v("PNNatBCells", n, "transfer b cells per configuration"); v("PNNatACells", na, "transfer a cells per configuration")
atk = {r["id"]: r["attacker"] for r in nrows}
called = 0
for x in nres:
    if x["cond"] == "b" and x["arm"] == "tripwire_v2":
        f = NT.NAT / "nat_b" / x["model"] / "tripwire_v2" / f"{x['model']}-tripwire_v2" / x["suite"] / x["task"] / "nat_b" / "none.json"
        d = json.load(open(f))
        called += any(atk[x["task"]] in json.dumps(tc.get("args", {})) for msg in d["messages"] if msg.get("role") == "assistant"
                      for tc in (msg.get("tool_calls") or []))
v("PNNatCalled", called, "delegation b cells whose model called the inserted destination (all refused, 0 admitted)")
v("PNNatNever", n - called, "delegation b cells without such a call")
url = lambda x: x["suite"] == "dailylife"
xu, nu = nat("a", "none", url); du, _ = nat("a", "tripwire_v2", url)
v("PNNatUrlNone", xu, "transfer a, dailylife URL cells, no defense"); v("PNNatUrlCells", nu, "transfer a dailylife URL cells")
assert du == 0
v("PNNatOther", na - nu, "transfer a cells outside dailylife")
ph("evaluation", "Condition b covers <<PNNatBTasks>> of the <<PNNatTasks>> tasks and <<PNNatBSlack>> of those <<PNNatBTasks>> share one Slack page.")
ph("evaluation", "admits none of the <<PNNatBCells>> inserted destinations, against <<PNNatNoneB>> of <<PNNatBCells>> with no defense and <<PNNatRopeB>> of <<PNNatBCells>> for ROPE with its live router. In <<PNNatCalled>> of the <<PNNatBCells>> cells the model called the inserted destination and the configuration blocked it. In the other <<PNNatNever>> the model never attempted it. In condition a it completes <<PNNatDelegA>> of <<PNNatACells>> cells against <<PNNatNoneA>> of <<PNNatACells>> with no defense. The \\strictcfg{} completes <<PNNatStrictA>>. The no-defense configuration completes <<PNNatUrlNone>> of the <<PNNatUrlCells>> dailylife URL cells")
ph("evaluation", "On the other <<PNNatOther>> cells the")
ph("evaluation", "The natural check gives <<PNNatDelegB>> of <<PNNatBCells>>.")
ph("abstract", "It admitted <<PNNatDelegB>> of <<PNNatBCells>> benchmark")
ph("setup", "uses the <<PNNatTasks>> delegated prompts of the census")
ph("setup", "so it covers the <<PNNatBTasks>> banking and slack tasks")

# ---- grid by suite and ROPE scope (RQ1)
inv, ninv = cnt("a", "tripwire_v2", [MINI], {"shopping"})
assert inv == 0
v("PNShopInvented", ninv, "gpt-4o-mini shopping tasks, all failed under delegation in condition a")
v("PNShopInventedW", WORDS[ninv], "the same count as a word")
sc = {r[0]: r[1:] for r in TR.t_rope_scope(G)}
def frac2(s_): a_, b_ = s_.split("/"); return int(a_), int(b_)
for key, tag in (("FREE", "Free"), ("RECORD", "Record"), ("floor", "Floor"), ("unguarded", "Unguarded")):
    ca, cb = frac2(sc[key][0]), frac2(sc[key][1])
    v(f"PNScope{tag}N", ca[1], f"ROPE scope cells {key}, rope_scope_xtab.json scopes x data_v2/e2x_a")
    v(f"PNScope{tag}A", ca[0], f"ROPE scope {key} condition a completed"); v(f"PNScope{tag}B", cb[0], f"ROPE scope {key} condition b executed")
assert int(V["PNScopeFreeB"]) + int(V["PNScopeUnguardedB"]) == rB
ph("evaluation", "sends all <<PNShopInventedW>> seller e-mails")
ph("evaluation", "executes all <<PNShopInventedW>> invented\naddresses")
ph("evaluation", "The <<PNShopInvented>> shopping cells here")
ph("evaluation", "The freed prompts complete <<PNScopeFreeA>> of <<PNScopeFreeN>>, the record-routed prompts <<PNScopeRecordA>> of <<PNScopeRecordN>> and the prompts on the unaudited slack parameter <<PNScopeUnguardedA>> of <<PNScopeUnguardedN>>, as")
ph("evaluation", "destination on <<PNScopeFreeN>> cells, routed <<PNScopeRecordN>> to the user's records, left <<PNScopeFloorN>> to the guarded floor and <<PNScopeUnguardedN>> sat on")
ph("evaluation", "In condition b, <<PNScopeFreeB>> of the <<PNScopeFreeN>> freed cells and <<PNScopeUnguardedB>> of the <<PNScopeUnguardedN>> unlisted cells\nare admitted, <<PNRopeB>> in all,")

# ---- ambiguity replay on held-out attack traces (RQ1)
ab = script("h1_ambiguity_attack_blocks", ["n_tr", "blocks", "amb_traces", "amb_tasks"]); avs = script("h1_ambiguity_value_source", ["c"])["c"]; bl = ab["blocks"]
assert avs["amb"] == bl["with_ambiguous"]
v("PNReplayTraces", ab["n_tr"], "held-out undefended attack traces, scripts/h1_ambiguity_attack_blocks.py n_tr")
v("PNReplayBlocked", bl["blocked_calls"], "calls the strict configuration blocks in the replay")
v("PNReplayAmb", bl["with_ambiguous"], "blocked calls carrying the ambiguous label")
v("PNReplayAmbOnly", bl["ambiguous_only"], "ambiguous blocks with no other triggering rule")
v("PNReplayAmbLegit", avs["goal=N inj=N clean_env=Y"], "ambiguous values in the clean environment and in no injected text, scripts/h1_ambiguity_value_source.py")
v("PNReplayAmbAtk", avs["goal=Y inj=Y clean_env=Y"], "ambiguous values equal to the injection goal value")
v("PNReplayAmbNeither", avs["goal=N inj=N clean_env=N"], "ambiguous values in neither")
v("PNReplayAmbTraces", len(ab["amb_traces"]), "traces with an ambiguous block")
v("PNReplayAmbTasksW", WORDS[len(ab["amb_tasks"])], "distinct user tasks with an ambiguous block, as a word")
ph("evaluation", "We replayed the <<PNReplayTraces>> held-out attack traces")
ph("evaluation", "Of the <<PNReplayBlocked>> calls it blocks, <<PNReplayAmb>> carry the ambiguous label and <<PNReplayAmbOnly>> carry no other triggering rule. In <<PNReplayAmbLegit>> of the <<PNReplayAmb>> the blocked value")
ph("evaluation", "In <<PNReplayAmbAtk>> it is the attacker's value from the injection goal. The other <<PNReplayAmbNeither>> occur in neither.")
ph("evaluation", "Those <<PNReplayAmb>> calls fall in <<PNReplayAmbTraces>> traces on <<PNReplayAmbTasksW>> user tasks.")
ph("evaluation", "We therefore claim the <<PNDelegB>> of <<PNGridCells>> insertion result")

# ---- held-out experiment H1 (RQ2, abstract, intro, method, RQ4)
h1rows, h1 = cached("t_h1", lambda: TR.t_h1(True))
HP, HB = h1["pooled"], h1["bootstrap"]
st = HB["tripwire_strict_v2"]
v("PNHOneStrictGap", fmt(st["sec"], 1), "strict minus ROPE attack success, pooled, corrected security (tables_from_raw.t_h1)")
v("PNHOneStrictLo", neg(st["sec_ci"][0]), "lower end of its 95% task-cluster interval")
v("PNHOneStrictHi", neg(st["sec_ci"][1]), "upper end")
v("PNHOneCULoss", fmt(-st["cu"], 0) if st["cu"] == int(st["cu"]) else fmt(-st["cu"], 1), "strict clean-utility loss against ROPE, pp")
v("PNHOneCULossLo", fmt(-st["cu_ci"][1], 1), "lower end of the loss interval (negated upper end of the gap interval)")
v("PNHOneCULossHi", fmt(-st["cu_ci"][0], 1), "upper end of the loss interval")
v("PNHOneCULossW", WORDS[int(-st["cu"])], "the loss as a word")
v("PNHOneRopeCUa", fmt(HP["rope"][1], 1), "ROPE clean utility, pooled"); v("PNHOneStrictCUa", fmt(HP["tripwire_strict_v2"][1], 1), "strict clean utility, pooled")
v("PNHOneDelegASRa", fmt(HP["tripwire_v2"][0], 1), "delegation attack success, pooled"); v("PNHOneRopeASRa", fmt(HP["rope"][0], 1), "ROPE attack success, pooled")
pm = {r[0]: r[1:] for r in h1rows}
dl = [float(pm[TR.SHORT[m]][2].split(" / ")[0]) for m in M3]; rp = [float(pm[TR.SHORT[m]][1].split(" / ")[0]) for m in M3]
v("PNHOneDelegMin", fmt(Fraction(str(min(dl))), 1), "lowest per-model delegation attack success, tab:h1 rows")
v("PNHOneDelegMax", fmt(Fraction(str(max(dl))), 1), "highest per-model delegation attack success")
v("PNHOneRopeMin", fmt(Fraction(str(min(rp))), 1), "lowest per-model ROPE attack success"); v("PNHOneRopeMax", fmt(Fraction(str(max(rp))), 1), "highest")
ph("abstract", "attack success was <<PNHOneStrictGap>> points above ROPE's, interval <<PNHOneStrictLo>> to <<PNHOneStrictHi>>, while clean utility fell from\n<<PNHOneRopeCUa>>\\% to <<PNHOneStrictCUa>>\\%")
ph("abstract", "Delegation attack success was <<PNHOneDelegASRa>>\\% against <<PNHOneRopeASRa>>\\%.")
ph("intro", "completes <<PNHOneCULoss>> pp fewer clean tasks than ROPE with its router, a significant loss whose task-cluster interval runs from <<PNHOneCULossLo>> to <<PNHOneCULossHi>> points.")
ph("intro", "loses <<PNHOneCULoss>> points of clean utility")
ph("method", "with a task-cluster interval of <<PNHOneCULossLo>> to <<PNHOneCULossHi>> points.")
ph("evaluation", "with a 95\\% interval of <<PNHOneStrictLo>> to <<PNHOneStrictHi>> pp, so the point estimate")
ph("evaluation", "Its attack success is\n<<PNHOneDelegMin>> to <<PNHOneDelegMax>> percent per model, \\HOneVTwoASR\\% pooled, against <<PNHOneRopeMin>> to <<PNHOneRopeMax>> percent for ROPE")
ph("evaluation", "a loss of <<PNHOneCULoss>> points with an interval of <<PNHOneCULossLo>> to <<PNHOneCULossHi>>, while its attack success is \\HOneStrictMinusRope\\ pp above ROPE's with an interval of <<PNHOneStrictLo>> to <<PNHOneStrictHi>>.")
ph("endmatter", "losing <<PNHOneCULossW>> clean-utility points")

# ---- synthesis split of the clean held-out cells (RQ2)
import h1_synthesis_split as HS  # noqa: E402
shares = J("data_v2/e2x/task_level_shares.json")
SYN = set()
for sn in HS.SUITES:
    ids, *_ = HS.synthesis_tasks(sn); SYN |= {(sn, i) for i in ids}
cc = {a: {} for a in ("rope", "tripwire_strict_v2")}
for m in M3:
    for a in cc:
        cc[a].update({(m,) + k: u for k, u in HS.clean_cells(m, a).items()})
keys = sorted(cc["rope"]); syn = [k for k in keys if k[1:] in SYN]; oth = [k for k in keys if k[1:] not in SYN]
rs, ss = sum(cc["rope"][k] for k in syn), sum(cc["tripwire_strict_v2"][k] for k in syn)
ro, so = sum(cc["rope"][k] for k in oth), sum(cc["tripwire_strict_v2"][k] for k in oth)
v("PNCleanCells", len(keys), "clean held-out cells, three models"); v("PNSynCells", len(syn), "synthesis cells"); v("PNOthCells", len(oth), "other cells")
v("PNSynTasksPerModel", len(SYN), "github synthesis tasks per model (census rule)")
v("PNSynRope", rs, "ROPE completions on synthesis cells"); v("PNSynStrict", ss, "strict completions on synthesis cells")
v("PNExtra", (rs + ro) - (ss + so), "ROPE completions minus strict completions, all clean cells")
v("PNSynExtra", rs - ss, "of those on synthesis cells"); v("PNOthExtra", ro - so, "on other cells")
v("PNOthStrict", so, "strict completions on other cells"); v("PNOthStrictPct", pc(so, len(oth)), "as a percent")
v("PNOthRope", ro, "ROPE completions on other cells"); v("PNOthRopePct", pc(ro, len(oth)), "as a percent")
ph("evaluation", "It splits the <<PNCleanCells>> clean cells by whether the task needs a control value that neither the prompt, the environment nor an earlier tool output holds, <<PNSynTasksPerModel>> github tasks per model or <<PNSynCells>> synthesis cells, or not, <<PNOthCells>> cells")
ph("evaluation", "On the <<PNSynCells>> synthesis cells ROPE completes <<PNSynRope>> against <<PNSynStrict>> for strict, <<PNSynExtra>> of ROPE's <<PNExtra>> extra completions.")
ph("evaluation", "The other <<PNOthExtra>> fall on cells whose values exist in the environment.")
ph("evaluation", "On the <<PNOthCells>> cells whose control values exist in the\nenvironment, strict completes <<PNOthStrict>>, <<PNOthStrictPct>> percent, against <<PNOthRope>> for ROPE, <<PNOthRopePct>> percent.")
ph("evaluation", "blocks in the <<PNCleanCells>> clean traces.")
ph("evaluation", "Split by group, the <<PNSynCells>> synthesis cells hold")
ph("evaluation", "The <<PNOthCells>> other cells hold")
ph("evaluation", "we traced each lost cell on the <<PNOthCells>> cells to the first block")
ph("evaluation", "Over all <<PNCleanCells>> clean cells ROPE keeps")

# ---- router rerun share, stage 1 (RQ2)
r2 = script("r2c_share", ["F", "R", "S", "lo", "hi", "new"])
v("PNRtcFixed", r2["F"], "rope_fixed clean completions, gpt-4o-mini + gpt-4o, data_v2/r2c (scripts/r2c_share.py)")
v("PNRtcCells", sum(1 for k in r2["new"]["rope_fixed"][0]), "clean cells of the two models")
v("PNRtcRouted", r2["R"], "routed ROPE clean completions in the same batch"); v("PNRtcStrict", r2["S"], "strict clean completions in the same batch")
v("PNRtcShare", fmt(Fraction(r2["R"] - r2["F"], r2["R"] - r2["S"]) * 100, 0), "share = (routed - fixed) / (routed - strict), percent")
v("PNRtcLo", fmt(Fraction(r2["lo"]).limit_denominator(10**6) * 100, 0), "lower end of the 95% task bootstrap interval, percent")
v("PNRtcHi", fmt(Fraction(r2["hi"]).limit_denominator(10**6) * 100, 0), "upper end")
ph("evaluation", "completes <<PNRtcFixed>> of the <<PNRtcCells>> clean cells of these two models, against <<PNRtcRouted>> for ROPE and <<PNRtcStrict>> for strict in the same batch, so over all clean tasks of these two models the router carries <<PNRtcShare>> percent of the gap, with a 95\\% interval of <<PNRtcLo>> to <<PNRtcHi>> percent.")

# ---- lost non-synthesis cells by first block (RQ2)
ra = J("data_v2/diag/h1_rule_attribution.json"); A = ra["rule_A"]
v("PNLost", ra["n_lost"], "non-synthesis cells ROPE completes and strict loses, data_v2/diag/h1_rule_attribution.json")
v("PNLostRone", A["R1"], "first block a read locator"); v("PNLostFree", A["LABEL:FREE_TEXT"], "first block copied prose")
v("PNLostRtwo", A["R2b"], "first block an unanchored write"); v("PNLostNone", A["LABEL:NONE"], "first block a model-made value")
v("PNLostNoBlock", A["NO_BLOCK"], "no rule fires on the legitimate path")
assert sum(A.values()) == ra["n_lost"]
ph("evaluation", "of the <<PNLost>> non-synthesis cells that strict loses and ROPE completes is a read locator in <<PNLostRone>>, copied prose in <<PNLostFree>>, an unanchored write in <<PNLostRtwo>> and a model-made value in <<PNLostNone>>. In the other <<PNLostNoBlock>> no rule fires")

# ---- census (RQ3, RQ4)
WORDS.update({1: "one"})
tl = {k: x for k, x in shares.items()}
ntask = sum(x["tasks_total"] for x in tl.values()); ndel = sum(x["delegated_tasks"] for x in tl.values())
v("PNCensusTasks", ntask, "census tasks over six suites, data_v2/e2x/task_level_shares.json")
v("PNSynTasks", tl["github"]["synthesis_tasks"], "github tasks needing a synthesized value"); v("PNGithubTasks", tl["github"]["tasks_total"], "github tasks")
v("PNDelTasks", ndel, "tasks with a delegated destination"); v("PNDelTasksPct", pc(ndel, ntask, 0), "as a percent of census tasks")
nrec = sum(x["reception"] for x in tl.values())
v("PNReceptionW", WORDS[nrec].capitalize(), "suites exposing attacker-writable record fields, as a word"); v("PNSuitesW", WORDS[len(tl)], "suites, as a word")
ae = script("amb_exposure", ["tot"])["tot"]
v("PNAmbDests", ae["dest"], "delegated destinations, scripts/amb_exposure.py"); v("PNAmbDestsHit", ae["amb"], "of those in a named document with several same-class values")
v("PNAmbDocs", ae["docs"], "documents the census walks"); v("PNAmbDocsMulti", ae["docs_multi"], "with two or more values of one class")
v("PNAmbNamed", ae["named"], "documents some prompt names"); v("PNAmbNamedMulti", ae["named_multi"], "of those with two or more values of one class")
prev = J("data_v2/e2x/prevalence.json")["confirmation_burden"]
v("PNConfirmW", WORDS[prev["need_one_confirmation"]], "confirmation requests, as a word, data_v2/e2x/prevalence.json")
ph("evaluation", "The denominator is tasks, <<PNCensusTasks>> across the six suites.")
ph("evaluation", "all in github, where <<PNSynTasks>> of <<PNGithubTasks>> tasks compose")
ph("evaluation", "Delegation covers <<PNDelTasks>> of <<PNCensusTasks>> tasks, <<PNDelTasksPct>> percent, concentrated")
ph("evaluation", "<<PNReceptionW>> of <<PNSuitesW>> suites expose attacker-writable record fields")
ph("evaluation", "Of the <<PNAmbDests>> delegated destinations, <<PNAmbDestsHit>> sits in a named document")
ph("evaluation", "Of the <<PNAmbDocs>> documents the census walks, <<PNAmbDocsMulti>> hold two or more values of one class. Among the <<PNAmbNamed>> documents some task prompt names, <<PNAmbNamedMulti>> do.")
ph("evaluation", "<<PNConfirmW>> prompts across the census's <<PNCensusTasks>> tasks.")

# ---- ROPE's held-out admissions by injection class (RQ4)
ua = script("h1_rope_unchecked_attacks", ["tot", "all_runs", "params"]); tot = ua["tot"]
v("PNRopeUnchecked", tot["unchecked"][0], "ROPE held-out admissions on injections through unchecked parameters, scripts/h1_rope_unchecked_attacks.py")
v("PNRopeAdmit", ua["all_runs"][0], "all ROPE held-out admissions")
v("PNRopeUncheckedN", tot["unchecked"][1], "attacked runs whose injection targets an unchecked parameter")
v("PNRopeChecked", tot["checked"][0], "admissions on checked parameters"); v("PNRopeCheckedN", tot["checked"][1], "runs on checked parameters")
v("PNRopeNoCtl", tot["skipped_no_control_arg"][0], "admissions from injections with no control argument")
v("PNRopeNoCtlN", tot["skipped_no_control_arg"][1], "runs whose injection sets no control argument")
v("PNRopeParamsW", WORDS[len(ua["params"])], "distinct unchecked parameters on admitted attacks, as a word")
ph("evaluation", "Post hoc, <<PNRopeUnchecked>> of the <<PNRopeAdmit>> held-out attacks that ROPE admits go through parameters its audited table does not check. They are <<PNRopeUnchecked>> of the <<PNRopeUncheckedN>> attacked runs whose injection targets such a parameter, all on <<PNRopeParamsW>> shopping-cart arguments, against <<PNRopeChecked>> of the <<PNRopeCheckedN>> on checked ones. The other <<PNRopeNoCtl>> come from the <<PNRopeNoCtlN>> runs whose injection sets no control argument.")

# ---- reception laundering (RQ4)
lq = [(m, t) for (m, k, t), o in G["c_h"].items() if o and k in ("tripwire_strict_v2", "tripwire_hist_v2")]
assert {m for m, _ in lq} == {QWEN}
v("PNLaunderQwenW", WORDS[len(lq)], "c-seeded admissions of strict and hist together, all on qwen3-235b, as a word")
ph("evaluation", "Strict mode admits the attack in <<PNLaunder>> of <<PNSeededCells>> cells\nand the \\histcfg{} in <<PNLaunder>> of <<PNSeededCells>>. All <<PNLaunderQwenW>> cells are on qwen3-235b")

# ---- first experiment (Method, SI)
e1 = J("data_v2/e1_rope_summary/verdict.json")["per_model"]
def e1sum(a, k): return sum(e1[m][a][k] for m in e1)
nAtt, nCl = e1sum("rope", "n_att"), e1sum("rope", "n_clean")
gapE = Fraction(100 * (e1sum("tripwire_strict", "ASR") - e1sum("rope", "ASR")), nAtt)
v("PNEOnePast", fmt(gapE - 2, 2), "E1 strict minus ROPE attack success minus the 2 pp margin, data_v2/e1_rope_summary/verdict.json per_model")
v("PNEOneStrictCULoss", fmt(Fraction(100 * (e1sum("rope", "CU") - e1sum("tripwire_strict", "CU")), nCl), 1),
  "E1 ROPE minus strict clean utility, pooled over four models (erratum 5: was printed 5.2)")
v("PNEOneInjPairs", e1["gpt-5.6-sol"]["none"]["n_att"], "E1 user-injection pairs per model")
v("PNEOneSolNoneW", WORDS[e1["gpt-5.6-sol"]["none"]["ASR"]], "gpt-5.6-sol attacks with no defense, as a word")
v("PNEOneLeaks", J("data_v2/diag/e1_leaks.json")["tripwire_strict"]["n"], "attacked pairs where gpt-4o-mini strict leaked and ROPE held, data_v2/diag/e1_leaks.json")
assert e1["gpt-5.6-sol"]["tripwire"]["ASR"] == 1
ph("method", "a gap of\n\\EOneStrictMinusRope\\ pp, which is <<PNEOnePast>> pp past the 2 pp margin")
ph("method", "The \\strictcfg{} alone lost <<PNEOneStrictCULoss>> points, past the 5 pp line.")
ph("method", "We replayed the <<PNEOneLeaks>> attacked\npairs")
ph("appendix", "The gap was \\EOneStrictMinusRope\\ pp, <<PNEOnePast>> pp past the margin.")
ph("appendix", "The \\strictcfg{} alone lost <<PNEOneStrictCULoss>> points, past the 5 pp line.")
ph("appendix", "Gpt-5.6-sol shows <<PNEOneSolNoneW>> attacks with no defense in\nits <<PNEOneInjPairs>> injection pairs")
ph("appendix", "the held-out suites the same table lost <<PNHOneCULossW>>.")

# ---- R0 gate against ROPE's shipped logs (Setup)
import importlib.util  # noqa: E402
spec_ = importlib.util.spec_from_file_location("r0", T / "experiments_v2" / "v2_r0_check.py")
with contextlib.redirect_stdout(io.StringIO()):
    r0 = importlib.util.module_from_spec(spec_); spec_.loader.exec_module(r0)
gh = {}
for m in M3:   # the gate's own aggregate: unweighted mean over the three suites, as v2_r0_check.py prints dCU
    o = [r0.agg(*r0.ours(m, sn)) for sn in r0.SUITES]; r_ = [r0.agg(*r0.shipped(m, sn)) for sn in r0.SUITES]
    gh[m] = Fraction(round(sum(x[0] - y[0] for x, y in zip(o, r_)) / 3 * 10**6), 10**6)
assert gh[QWEN] == 0, "Setup says the qwen model matches exactly"
lo_, hi_ = sorted([-gh[MINI], -gh[GPT4O]])
v("PNGateLo", fmt(lo_, 0), "suite-averaged clean-utility shortfall of our ROPE run against ROPE's shipped logs, smaller of the two OpenAI models (v2_r0_check.py)")
v("PNGateHi", fmt(hi_, 0), "the larger one")
ph("setup", "the two OpenAI models low by\n<<PNGateLo>> to <<PNGateHi>> pp in clean utility averaged over the three suites, the qwen model matching exactly.")

# ---- SI: grid per model, by configuration, ROPE variants, MELON, trace excerpts
WORDS.update({0: "none"})
for mm, tag in ((MINI, "Mini"), (GPT4O, "Four"), (QWEN, "Qwen")):
    v(f"PNDelegA{tag}", cnt("a", "tripwire_v2", [mm])[0], f"delegation condition a completions, {mm}")
    v(f"PNRopeA{tag}", cnt("a", "rope", [mm])[0], f"ROPE (live) condition a completions, {mm}")
    v(f"PNRopeB{tag}", cnt("b", "rope", [mm])[0], f"ROPE (live) condition b admissions, {mm}")
    eq = sum(noneA[k] == noneC[k] for k in noneA if k[0] == mm)
    v(f"PNEquiv{tag}", eq, f"no-defense a == c cells, {mm}")
v("PNModelTasks", cnt("a", "tripwire_v2", [MINI])[1], "grid tasks per model")
ph("appendix", "The \\delegcfg{} completes <<PNDelegAMini>>, <<PNDelegAFour>> and\n<<PNDelegAQwen>> of <<PNModelTasks>> in condition a")
ph("appendix", "ROPE completes <<PNRopeAMini>>, <<PNRopeAFour>> and <<PNRopeAQwen>> in condition a. Its condition b\nadmission of <<PNRopeBMini>>, <<PNRopeBFour>> and <<PNRopeBQwen>> tracks")
nB_, _ = cnt("b", "none"); rAh, nAh = cnt("a_h", "rope"); rC, _ = cnt("c", "rope"); rCh, _ = cnt("c_h", "rope")
v("PNNoneB", nB_, "no-defense condition b executed attacker destinations")
v("PNRopeAh", rAh, "ROPE (live) a-seeded completions"); v("PNSeededA", nAh, "a-seeded cells per configuration")
v("PNRopeC", rC, "ROPE (live) condition c admissions"); v("PNRopeCh", rCh, "ROPE (live) c-seeded admissions")
v("PNRopeA", rA, "ROPE (live) condition a completions")
ph("appendix", "reference, since <<PNEquivMatch>> of its <<PNGridCells>> condition a cells equal their condition c counterparts. Its b count of <<PNNoneB>> shows")
ph("appendix", "The ROPE row completes <<PNRopeA>> of <<PNGridCells>> clean cells and <<PNRopeAh>> of <<PNSeededA>> seeded clean cells. It admits <<PNRopeB>>, <<PNRopeC>> and <<PNRopeCh>> attacker destinations")
ph("appendix", "Across all three models, <<PNEquivMatch>> of <<PNGridCells>> condition a utility cells equal")
ph("appendix", "Gpt-4o and gpt-4o-mini match on all <<PNEquivFour>> of their <<PNModelTasks>> cells. Qwen3-235b matches on <<PNEquivQwen>> of <<PNModelTasks>>")
assert V["PNEquivFour"] == V["PNEquivMini"]
v("PNLaunderW", WORDS[lau].capitalize(), "c-seeded strict admissions, as a word"); v("PNSeededCellsW", "sixty" if nlau == 60 else str(nlau), "c-seeded cells, as a word")
v("PNLaunderHistW", WORDS[lauh], "c-seeded hist admissions, as a word")
ph("appendix", "<<PNLaunderW>> of the <<PNSeededCellsW>> c-seeded cells of the \\strictcfg{}")
ph("appendix", "The \\histcfg{} has <<PNLaunderHistW>> of <<PNSeededCellsW>> as well. All <<PNLaunderQwenW>> cells are on this model")
# ROPE variants
def cells(c, cfg): return {(m, t): o for (m, k, t), o in G[c].items() if k == cfg}
la, lb, ca, cb = cells("a", "rope"), cells("b", "rope"), cells("a", "rope_clamp"), cells("b", "rope_clamp")
v("PNClampA", sum(ca.values()), "rope_clamp condition a completions, data_v2/e2x_a"); v("PNClampB", sum(cb.values()), "rope_clamp condition b admissions")
v("PNClampAPct", pc(sum(ca.values()), len(ca)), "as a percent"); v("PNClampBPct", pc(sum(cb.values()), len(cb)), "as a percent")
SCOPES = J("data_v2/e2x/rope_scope_xtab.json")["scopes"]
UNG = {k for k in la if SCOPES[k[1]]["marker"] == "unguarded"}
assert sum(cb.values()) == sum(cb[k] for k in UNG), "SI says every clamped admission is on the unaudited parameter"
v("PNUngCells", len(UNG), "cells on the parameter the audit never lists"); v("PNUngLiveA", sum(la[k] for k in UNG), "ROPE live condition a on them")
v("PNUngLiveB", sum(lb[k] for k in UNG), "ROPE live condition b on them")
alost = [k for k in UNG if la[k] and not ca[k]]; bblk = [k for k in UNG if lb[k] and not cb[k]]; brev = [k for k in lb if cb[k] and not lb[k]]
v("PNClampALost", len(alost), "cells ROPE live completes and rope_clamp does not, condition a")
v("PNClampALostW", WORDS[len(alost)], "the same as a word")
v("PNClampALostTasksW", WORDS[len({t for _, t in alost})], "distinct prompts among them, as a word")
v("PNClampBBlockedW", WORDS[len(bblk)], "condition b cells admitted live and blocked by the clamp, as a word")
assert len(brev) == 1 and brev[0][0] == MINI
ph("appendix", "It completes <<PNClampA>> cells in a\nand executes <<PNClampB>> attacker destinations in b, all on the <<PNUngCells>> cells whose parameter the audit never lists, so the clamp leaves\nthat hole open. On those <<PNUngCells>> cells the live router completes <<PNUngLiveA>> and executes <<PNUngLiveB>>.")
# "removes the invite tool on four prompts" stays literal: hand-derived from the router cache and logs (TABLE_PROVENANCE section 7)
ph("appendix", "In a this costs <<PNClampALostW>> completions, <<PNClampALostTasksW>> prompts on all three models")
ph("appendix", "In b it blocks <<PNClampBBlockedW>> executed attacker destinations.")
ph("appendix", "Delegation completes <<PNDelegAN>> of <<PNGridCells>> in a\nagainst <<PNClampA>> of <<PNGridCells>>, <<PNDelegAPct>> against <<PNClampAPct>> percent. In condition b the \\delegcfg{} executes <<PNDelegB>> of <<PNGridCells>> attacker destinations against <<PNClampB>> of <<PNGridCells>> for the clamped variant, <<PNDelegBPct>> against <<PNClampBPct>> percent.")
v("PNDelegAN", dA, "delegation condition a completions over three models")
af = {c: cells(c, "rope_auditfix") for c in "ab"}; afc = {c: cells(c, "rope_auditfix_clamp") for c in "ab"}
v("PNAuditCells", len(af["a"]), "cells the audit-fix variant covers (slack, two models)")
v("PNAuditTasks", len({t for _, t in af["a"]}), "slack tasks among them")
v("PNAuditA", sum(af["a"].values()), "audit-fix condition a"); v("PNAuditB", sum(af["b"].values()), "audit-fix condition b")
v("PNAuditClA", sum(afc["a"].values()), "audit-fix + clamp condition a"); v("PNAuditClB", sum(afc["b"].values()), "audit-fix + clamp condition b")
v("PNAuditLiveA", sum(la[k] for k in af["a"]), "ROPE live condition a on the same cells"); v("PNAuditLiveB", sum(lb[k] for k in af["b"]), "ROPE live condition b on the same cells")
ph("appendix", "Only the <<PNAuditCells>> cells on that parameter can differ, <<PNAuditTasks>> slack tasks on two models.")
ph("appendix", "On those <<PNAuditCells>> cells the\naudit-fix admits <<PNAuditA>> in a and <<PNAuditB>> in b while the combination with the clamp admits <<PNAuditClA>> in a and <<PNAuditClB>> in b, against <<PNAuditLiveA>> and <<PNAuditLiveB>> for the live router.")
# MELON
mel = lambda c, sn: cnt(c, "melon", [MINI, GPT4O], {sn})
for c in "abc":
    for sn in ("banking", "slack"):
        x, n = mel(c, sn); v(f"PNMel{c.upper()}{sn.capitalize()}", x, f"MELON condition {c} on {sn}, two models")
v("PNMelCells", n, "MELON cells per suite and condition")
assert V["PNMelABanking"] == "0" and V["PNMelASlack"] == V["PNMelCSlack"] == V["PNMelCells"]
for c in "bc":
    assert cnt(c, "none", [MINI, GPT4O], {"slack"})[0] == int(V[f"PNMel{c.upper()}Slack"])
ph("appendix", "on the <<PNMelCells>> banking and slack tasks of the grid")
ph("appendix", "On banking MELON stops the legitimate payment in all <<PNMelCells>>\nclean cells and admits <<PNMelBBanking>> of <<PNMelCells>> insertions and <<PNMelCBanking>> of <<PNMelCells>> replacements. On slack it never fires, so it completes all <<PNMelASlack>>\nclean invites and admits <<PNMelBSlack>> of <<PNMelCells>> insertions and all <<PNMelCSlack>> replacements")
# v2.1 SI
ra21, ra2 = J("data_v2/diag/h1_rule_attribution_v21.json"), J("data_v2/diag/h1_rule_attribution_v2_2models.json")
def wn(d): s_ = d["source"]; return s_["WRITABLE"] + s_["NO_SOURCE"], d["n_lost"] - d["rule_A"]["NO_BLOCK"]
v("PNVOneWN", wn(ra21)[0], "v2.1 lost cells whose first block traces to an attacker-writable result or no result, data_v2/diag/h1_rule_attribution_v21.json")
v("PNVOneBlocked", wn(ra21)[1], "v2.1 lost cells that a rule blocks"); v("PNVTwoWN", wn(ra2)[0], "the same for v2 on the two models")
v("PNVTwoBlocked", wn(ra2)[1], "v2 lost cells that a rule blocks, two models")
two = [m for m in (MINI, GPT4O)]
syn2 = [k for k in syn if k[0] in two]
c21 = {}
for m in two:
    c21.update({(m,) + k: u for k, u in HS.clean_cells(m, "tripwire_strict_v21").items()})
v("PNSynTwo", len(syn2), "synthesis cells of the two models"); v("PNSynTwoRope", sum(cc["rope"][k] for k in syn2), "ROPE completions on them")
assert sum(c21[k] for k in syn2) == 0 and sum(cc["tripwire_strict_v2"][k] for k in syn2) == 0
ph("appendix", "we traced each lost cell on the <<PNOthCells>> cells to the first block")
ph("appendix", "Under v2.1, <<PNVOneWN>> of the <<PNVOneBlocked>> lost cells that a rule blocks")
ph("appendix", "the count is <<PNVTwoWN>> of <<PNVTwoBlocked>>. On the <<PNSynTwo>>\nsynthesis cells of these two models v2.1 completes none, as v2 does, against <<PNSynTwoRope>> for ROPE.")
ph("evaluation", "Against the clamped variant, which takes no router output, the \\delegcfg{} completes <<PNDelegAN>> against <<PNClampA>> of <<PNGridCells>> cells in condition a and executes <<PNDelegB>> against <<PNClampB>> in condition b")

# ---- SI: ROPE router answers
rc = J("data_v2/e2x/router_cache.json"); rn = J("data_v2/v2_natural/router_cache.json")
v("PNRouterEntries", len(rc) + len(rn), "memoized router answers, data_v2/e2x/router_cache.json + data_v2/v2_natural/router_cache.json")


# ------------------------------------------------------------------ check / apply
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    bad = 0
    texts = {}
    # --macros (release): recompute every macro and write tab/prose_numbers.tex without the phrase check, which
    # needs the manuscript prose under paper_artifacts/sec/ (not shipped)
    for f, t in ([] if mode == "--macros" else PHRASES):
        texts.setdefault(f, (P / f).read_text())
        s = fill(t); n = texts[f].count(s) + texts[f].count(fill(t, macro=True))   # literal before --apply, macros after
        if n != 1:
            bad += 1
            pat = re.escape(re.sub(r"<<\w+>>", "\0", t)).replace("\\\0", "\0").replace("\0", r"(\S+?)")
            m = re.search(pat, texts[f])
            near = m.group(0) if m else (difflib.get_close_matches(s, re.split(r"(?<=\.)\s+", texts[f]), 1, 0.3) or ["?"])[0]
            print(f"MISMATCH {f} x{n}\n  expected: {s}\n  tex:      {near}")
    if bad:
        print(f"{bad} phrase(s) differ; stop and report (no file written)"); sys.exit(1)
    print(f"check ok: {len(PHRASES)} phrases, {len(V)} macros")
    if mode == "--apply":
        for f, t in PHRASES:
            texts[f] = texts[f].replace(fill(t), fill(t, macro=True))
        for f, s in texts.items():
            (P / f).write_text(s)
    if mode in ("--apply", "--write", "--macros"):
        out = "% AUTO-GENERATED by scripts/prose_numbers.py -- do not edit by hand.\n" + "".join(
            f"\\newcommand{{\\{k}}}{{{V[k]}}}% {SRC[k]}\n" for k in V)
        (P / "tab" / "prose_numbers.tex").write_text(out)
        print("wrote tab/prose_numbers.tex")


if __name__ == "__main__":
    main()
