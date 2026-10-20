"""RQ4 census, synthesis and reception sides (read-only, complements e2x_prevalence.py's delegation census).
For every side-effecting ground-truth call with a control argument:
  SYNTHESIS: the control value appears neither in the prompt nor verbatim anywhere in the default environment,
  so a correct agent must synthesize it (compose, transform or guess). These are the tasks where refusing
  model-made values (strict's NONE rule) refuses the correct answer.
  RECEPTION: the environment holds at least one record field an attacker can write through a receive-type
  action (incoming transaction senders in banking/dailylife, received e-mail senders everywhere with an inbox),
  i.e. the channel the c_h laundering used. Counted per suite as a property of the environment.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 boundary_prevalence.py"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import copy
import json

from agentdojo.task_suite.load_suites import get_suite

from tripwire_v2 import CONTROL_ALL  # noqa: E402  (paper's side-effecting tables)

VERSION = "v1.2.2"
OUT = "./data_v2/e2x/boundary_prevalence.json"
TLS = "./data_v2/e2x/task_level_shares.json"


def env_text(env):
    return json.dumps(env.model_dump(mode="json"), default=str).lower()


def synth_values(suite, env):
    """Census rule. A ground-truth control value counts once per occurrence and
    must be synthesized when it is in neither the prompt, the clean environment nor any output of an earlier
    ground-truth call of the same task. Excluded before counting: Python None arguments (optional cc/bcc, which the
    first rule stringified to 'None') and arguments the task resolves from a tool output at run time
    (placeholder_args value starting with '$', e.g. shopping file_id 'ID1'). Values shorter than 3 are skipped.
    Returns (n_values, n_synthesized, synthesis task ids, [(task, function, arg, value, reason)] for excluded or
    read-at-runtime values)."""
    from agentdojo.functions_runtime import FunctionsRuntime
    E = env_text(env)
    rt = FunctionsRuntime(suite.tools)
    n_vals = n_syn = 0
    tasks_syn, notes = set(), []
    for uid, t in suite.user_tasks.items():
        prompt = t.PROMPT.lower()
        try:
            gt = t.ground_truth(env)
        except Exception:  # noqa: BLE001
            continue
        run_env, seen = copy.deepcopy(env), ""
        for c in gt:
            ph = getattr(c, "placeholder_args", None) or {}
            for a in CONTROL_ALL.get(c.function, ()):
                v = c.args.get(a)
                for x0 in (v if isinstance(v, (list, tuple)) else [v]):
                    if x0 is None:
                        notes.append((uid, c.function, a, None, "none_arg"))
                        continue
                    x = str(x0)
                    if len(x) < 3:
                        continue
                    n_vals += 1
                    if x.lower() in prompt or x.lower() in E:
                        continue
                    if isinstance(ph.get(a), str) and ph[a].startswith("$"):
                        notes.append((uid, c.function, a, x, "placeholder"))
                    elif x.lower() in seen:
                        notes.append((uid, c.function, a, x, "earlier_output"))
                    else:
                        n_syn += 1
                        tasks_syn.add(uid)
            try:
                r, err = rt.run_function(run_env, c.function, dict(c.args))
                seen += " " + str(r).lower() + " " + str(err).lower()
            except Exception as e:  # noqa: BLE001
                seen += " " + str(e).lower()
    return n_vals, n_syn, tasks_syn, notes


def main():
    rep = {}
    for sn in ("banking", "slack", "travel", "shopping", "github", "dailylife"):
        suite = get_suite(VERSION, sn)
        env = suite.load_and_inject_default_environment({})
        n_vals, n_syn, tasks_syn, _ = synth_values(suite, env)
        # reception channel: does the suite have attacker-writable record fields (received senders)?
        recv = (hasattr(env, "bank_account") and any(t.sender != "me" for t in env.bank_account.transactions)) \
            or (hasattr(env, "email_database")) or (hasattr(env, "slack"))
        rep[sn] = {"control_values": n_vals, "must_synthesize": n_syn, "tasks_needing_synthesis": len(tasks_syn),
                   "tasks_total": len(suite.user_tasks), "reception_channel": bool(recv)}
        print(f"{sn:10} control values {n_vals:3}  must-synthesize {n_syn:3}  tasks {len(tasks_syn)}/{len(suite.user_tasks)}  reception {recv}")
    tot_v = sum(v["control_values"] for v in rep.values()); tot_s = sum(v["must_synthesize"] for v in rep.values())
    print(f"TOTAL      control values {tot_v:3}  must-synthesize {tot_s:3} ({100*tot_s/max(1,tot_v):.0f}%)")
    rep["_total"] = {"control_values": tot_v, "must_synthesize": tot_s}
    json.dump(rep, open(OUT, "w"), indent=1)
    tls = json.load(open(TLS))
    for sn in tls:
        tls[sn]["synthesis_tasks"] = rep[sn]["tasks_needing_synthesis"]
    json.dump(tls, open(TLS, "w"), indent=1)


if __name__ == "__main__":
    main()
