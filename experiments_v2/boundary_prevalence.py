"""RQ4 census, synthesis and reception sides (read-only, complements e2x_prevalence.py's delegation census).
For every side-effecting ground-truth call with a control argument:
  SYNTHESIS: the control value appears neither in the prompt nor verbatim anywhere in the default environment,
  so a correct agent must synthesize it (compose, transform or guess). These are the tasks where refusing
  model-made values (strict's NONE rule) refuses the correct answer.
  RECEPTION: the environment holds at least one record field an attacker can write through a receive-type
  action (incoming transaction senders in banking/dailylife, received e-mail senders everywhere with an inbox),
  i.e. the channel the c_h laundering used. Counted per suite as a property of the environment.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 boundary_prevalence.py"""
import json

from agentdojo.task_suite.load_suites import get_suite

from tripwire_v2 import CONTROL_ALL  # noqa: E402  (paper's side-effecting tables)

VERSION = "v1.2.2"
OUT = "./data/e2x/boundary_prevalence.json"


def env_text(env):
    return json.dumps(env.model_dump(mode="json"), default=str).lower()


def main():
    rep = {}
    for sn in ("banking", "slack", "travel", "shopping", "github", "dailylife"):
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


if __name__ == "__main__":
    main()
