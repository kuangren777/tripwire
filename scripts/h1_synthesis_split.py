"""Post-hoc RQ2 diagnosis of the held-out H1 experiment: split the 180 clean cells (60 tasks x 3 models) by the
task-level synthesis label of the RQ3 census, and report clean utility for rope and the strict arm on each part.
Read-only. Inputs:
  data/v2_heldout/{model}/{arm}/*/{suite}/user_task_*/none/none.json   clean cells (same glob as v2_h1_decision.py)
  boundary_prevalence.py                                               census rule (env_text, CONTROL_ALL, loop below)
  data/e2x/task_level_shares.json, data/e2x/boundary_prevalence.json   cross-check of the recomputed task labels
  data/v2_heldout/decision.json                                        cross-check of the pooled CU
The census JSONs store counts only, so the per-task labels are recomputed with boundary_prevalence.py's own rule
(the loop in synthesis_tasks() mirrors boundary_prevalence.main line for line) and asserted against the stored counts.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 scripts/h1_synthesis_split.py  (from paper-tripwire/)"""
import glob, json, os, sys

sys.dont_write_bytecode = True  # keep the project tree untouched
T = "."
sys.path.insert(1, T)
for p in ("../ext/rope/autodojo/src", "../ext/rope/src"):
    if p not in sys.path:
        sys.path.insert(1, p)

from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from boundary_prevalence import VERSION, CONTROL_ALL, env_text  # noqa: E402

D = f"{T}/data/v2_heldout"
MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-08-06", "qwen3-235b-a22b-instruct-2507"]
SUITES = ("shopping", "github", "dailylife")
ARMS = {"rope": "rope", "strict": "tripwire_strict_v2"}


def synthesis_tasks(sn):
    """boundary_prevalence.main's SYNTHESIS rule for one suite -> (task ids, n_values, n_synthesize)."""
    suite = get_suite(VERSION, sn)
    env = suite.load_and_inject_default_environment({})
    E = env_text(env)
    n_vals = n_syn = 0
    tasks_syn = set()
    for uid, t in suite.user_tasks.items():
        prompt = t.PROMPT.lower()
        try:
            gt = t.ground_truth(env)
        except Exception:  # noqa: BLE001
            continue
        for c in gt:
            for a in CONTROL_ALL.get(c.function, ()):
                v = c.args.get(a)
                for x in (v if isinstance(v, (list, tuple)) else [v]):
                    x = str(x)
                    if len(x) < 3:
                        continue
                    n_vals += 1
                    if x.lower() not in prompt and x.lower() not in E:
                        n_syn += 1
                        tasks_syn.add(uid)
    return tasks_syn, n_vals, n_syn, len(suite.user_tasks)


def clean_cells(model, arm):
    """(suite, task) -> utility, clean cells only; identical path parsing to v2_h1_decision.load."""
    out = {}
    for f in glob.glob(f"{D}/{model}/{arm}/*/*/user_task_*/*/*.json"):
        p = f.split("/")
        if p[-2] != "none":
            continue
        d = json.load(open(f))
        if "utility" not in d:
            raise SystemExit(f"unfinished cell {f}")
        out[(p[-4], p[-3])] = bool(d["utility"])
    return out


def main():
    shares = json.load(open(f"{T}/data/e2x/task_level_shares.json"))
    bp = json.load(open(f"{T}/data/e2x/boundary_prevalence.json"))
    dec = json.load(open(f"{T}/data/v2_heldout/decision.json"))

    SYN = set()
    for sn in SUITES:
        ids, nv, ns, nt = synthesis_tasks(sn)
        assert len(ids) == shares[sn]["synthesis_tasks"] == bp[sn]["tasks_needing_synthesis"], sn
        assert (nv, ns, nt) == (bp[sn]["control_values"], bp[sn]["must_synthesize"], bp[sn]["tasks_total"]), sn
        SYN |= {(sn, i) for i in ids}
        print(f"census {sn:10} synthesis tasks {len(ids)}/{nt}: {', '.join(sorted(ids, key=lambda s: int(s.split('_')[-1])))}")
    print(f"census held-out synthesis tasks {len(SYN)} (matches task_level_shares.json and boundary_prevalence.json)")

    cnt = {a: {"syn": [0, 0], "other": [0, 0]} for a in ARMS}
    for a, arm in ARMS.items():
        for m in MODELS:
            cells = clean_cells(m, arm)
            assert len(cells) == 60 and sum(cells.values()) == dec["per_model"][m][arm]["CU"], (m, arm)
            for key, ok in cells.items():
                part = "syn" if key in SYN else "other"
                cnt[a][part][0] += ok
                cnt[a][part][1] += 1

    N = sum(cnt["rope"][k][1] for k in ("syn", "other"))
    print(f"\nclean cells {N} = {len(MODELS)} models x {N // len(MODELS)} tasks")
    for part, name in (("syn", "synthesis"), ("other", "other")):
        r, s = cnt["rope"][part], cnt["strict"][part]
        assert r[1] == s[1]
        print(f"{name:9} cells {r[1]:3}  rope {r[0]:3}/{r[1]} ({100*r[0]/r[1]:.1f}%)  "
              f"strict {s[0]:3}/{s[1]} ({100*s[0]/s[1]:.1f}%)")
    pr = sum(cnt["rope"][k][0] for k in cnt["rope"]); ps = sum(cnt["strict"][k][0] for k in cnt["strict"])
    assert round(100 * pr / N, 2) == dec["pooled"]["rope"]["CU"] and round(100 * ps / N, 2) == dec["pooled"]["tripwire_strict_v2"]["CU"]
    print(f"pooled    cells {N:3}  rope {pr:3}/{N} ({100*pr/N:.1f}%)  strict {ps:3}/{N} ({100*ps/N:.1f}%)  "
          f"gap {100*(pr-ps)/N:.1f} pp")
    # contribution of each part to the pooled gap = cell share x within-part gap = (rope - strict successes) / N
    for part, name in (("syn", "synthesis"), ("other", "other")):
        r, s = cnt["rope"][part], cnt["strict"][part]
        print(f"gap contribution {name:9} {100*(r[0]-s[0])/N:.1f} pp  "
              f"(share {r[1]}/{N} x within-part gap {100*(r[0]/r[1]-s[0]/s[1]):.1f} pp)")


if __name__ == "__main__":
    main()
