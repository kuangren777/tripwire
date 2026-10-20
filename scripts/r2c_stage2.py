"""Amendment 7b (EXPERIMENT_PLAN_v2.md section 10.2): attack success of rope_fixed against routed ROPE on the attacked
held-out cells of gpt-4o-mini and gpt-4o. $0, reads logs only.
- rope_fixed: data_v2/r2c/<model>/rope_fixed/ (stage 2 batch). routed: data_v2/v2_heldout/<model>/rope/ (held-out run, not rerun).
- Outcome: ROPE's corrected security, as tab:h1 / tables_from_raw.py. Error or unfinished cells count as failed runs and
  are printed; a missing cell blocks the analysis.
- Consistency gate: per cell, the injections dict, benchmark_version and agentdojo_package_version must
  equal the reference. Any mismatch prints COMPARISON VOID and only the rope_fixed counts.
- Paired task-cluster bootstrap of fixed minus routed in pp, cluster = (suite, user task) over both models, 10,000
  resamples, Random(0), percentile interval. Split by injection class as scripts/h1_rope_unchecked_attacks.py.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/r2c_stage2.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, random, re, sys
from fractions import Fraction
from pathlib import Path

T = Path(".")
sys.path[:0] = [str(T), "ext/rope/runs", "scripts"]
from corrections import corrected_security  # noqa: E402
from fmtnum import fmt  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from boundary_prevalence import VERSION, CONTROL_ALL  # noqa: E402
from rope.scopes_io import load_floor  # noqa: E402

MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06"]
SUITES = ("shopping", "github", "dailylife")
B, SEED = 10_000, 0


def load(root, model, cfg):
    out, meta, errs = {}, {}, []
    for sn in SUITES:
        for f in glob.glob(f"{T}/{root}/{model}/{cfg}/*/{sn}/user_task_*/important_instructions/injection_task_*.json"):
            p = f.split("/"); d = json.load(open(f))
            if "security" not in d or d.get("error"):
                errs.append(f)
            v = bool(corrected_security(d, sn, int(re.sub(r"\D", "", p[-1][:-5]))))
            k = (model, sn, p[-3], p[-1][:-5])
            out[k] = v
            meta[k] = (d.get("injections"), d.get("benchmark_version"), d.get("agentdojo_package_version"))
    return out, meta, errs


def classes():
    cls = {}
    for sn in SUITES:
        suite = get_suite(VERSION, sn); env = suite.load_and_inject_default_environment({}); floor = load_floor(sn)
        for iid, it in suite.injection_tasks.items():
            un = []
            for c in it.ground_truth(env):
                for a in CONTROL_ALL.get(c.function, ()):
                    if c.args.get(a) is None:
                        continue
                    guarded = c.function in floor and a in floor[c.function] and floor[c.function][a][0] not in ("free",)
                    un.append(not guarded)
            cls[(sn, iid)] = ("unchecked" if any(un) else "checked") if un else "no_control_arg"
    return cls


def main():
    fx, rt, mf, mr, ef, er = {}, {}, {}, {}, [], []
    for m in MODELS:
        a, b, c = load("data_v2/r2c", m, "rope_fixed"); fx.update(a); mf.update(b); ef += c
        a, b, c = load("data_v2/v2_heldout", m, "rope"); rt.update(a); mr.update(b); er += c
    print(f"cells: rope_fixed {len(fx)}, routed {len(rt)}; error cells rope_fixed {len(ef)}, routed {len(er)}")
    for f in ef:
        print("  error/unfinished (counted as failed run):", f)
    missing = sorted(set(rt) - set(fx))
    if len(rt) != 1120 or missing:
        raise SystemExit(f"BLOCKED: routed {len(rt)} cells, {len(missing)} missing from rope_fixed, e.g. {missing[:3]}")
    mism = [k for k in rt if mf[k] != mr[k]]
    for m in MODELS:
        ks = [k for k in fx if k[0] == m]
        print(f"{m}: rope_fixed {sum(fx[k] for k in ks)}/{len(ks)}  routed {sum(rt[k] for k in ks)}/{len(ks)}")
    F, R = sum(fx.values()), sum(rt.values())
    print(f"pooled: rope_fixed {F}/1120 = {fmt(Fraction(100 * F, 1120), 1)}%  routed {R}/1120 = {fmt(Fraction(100 * R, 1120), 1)}%")
    cls = classes()
    split = collections.defaultdict(lambda: [0, 0, 0])
    for k in rt:
        s = split[cls[(k[1], k[3])]]; s[0] += fx[k]; s[1] += rt[k]; s[2] += 1
    print("by injection class [rope_fixed, routed, cells]:", dict(split))
    print("cells where rope_fixed and routed differ: fixed only", sum(fx[k] and not rt[k] for k in rt),
          "routed only", sum(rt[k] and not fx[k] for k in rt))
    if mism:
        print(f"COMPARISON VOID: {len(mism)} cells differ from the reference in injections or versions, e.g. {mism[:3]}")
        return
    print("consistency: injections, benchmark_version and agentdojo_package_version equal on all 1120 cells")
    by = collections.defaultdict(list)
    for k in sorted(rt):
        by[(k[1], k[2])].append(k)
    tasks = sorted(by)

    def gap(ts):
        n = d = 0
        for t in ts:
            for k in by[t]:
                n += fx[k] - rt[k]; d += 1
        return Fraction(100 * n, d)
    g0 = gap(tasks); rng = random.Random(SEED)
    gs = sorted(gap([tasks[rng.randrange(len(tasks))] for _ in tasks]) for _ in range(B))
    lo, hi = gs[int(0.025 * B)], gs[int(0.975 * B) - 1]
    print(f"fixed minus routed: {fmt(g0, 1)} pp, 95% task-cluster interval {fmt(lo, 1)} to {fmt(hi, 1)} pp")
    ok = Fraction(100 * F, 1120) <= Fraction(100 * R, 1120) + 2
    print("CRITERION (fixed <= routed + 2 pp):", "PASS" if ok else "FAIL")
    print("PREDICTION (fixed 15..25 of 1120):", "held" if 15 <= F <= 25 else "failed")
    u = split["unchecked"]
    print("PREDICTION (unchecked class within 3 of routed):", "held" if abs(u[0] - u[1]) <= 3 else "failed")
    # macros the RQ2 clause prints: one ROUND_HALF_UP via fmtnum, written to the S&S bridge
    assert u[0] == F, "RQ2 text says every rope_fixed admission is on an unchecked parameter"
    neg = lambda v: ("$-$" if v < 0 else "") + fmt(abs(v), 1)
    mac = {"RTwoCAttacked": str(len(rt)), "RTwoCFixedAdm": str(F), "RTwoCRoutedAdm": str(R),
           "RTwoCGap": neg(g0), "RTwoCCILo": neg(lo), "RTwoCCIHi": neg(hi)}
    open(f"{T}/paper_artifacts/tab/r2c_numbers.tex", "w").write(
        "% AUTO-GENERATED by scripts/r2c_stage2.py -- do not edit by hand.\n"
        + "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in mac.items()))
    print("wrote tab/r2c_numbers.tex:", mac)


if __name__ == "__main__":
    main()
