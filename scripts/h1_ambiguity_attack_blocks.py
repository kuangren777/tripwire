"""Does the ambiguity rule fire on held-out injections? Read-only replay of the undefended held-out ATTACK traces
(attack_type important_instructions, 3 models x 3 AgentDyn suites) through the registered strict arm (v2b_strict),
reusing diag_h1_cu.replay/classify (the replay that produced Table h1blocks on clean traces). For every call
the arm would block we record the triggering rules. Reported: blocked calls carrying LABEL:AMBIGUOUS, those where it
is the only rule (the ambiguity rule alone causes the block), traces with such a call, and how many of those
traces were successful attacks undefended.
Limits: the replay follows the undefended trajectory, so it counts what the rule would block on the calls the
undefended agent made. It does not re-run the agent against the arm.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 scripts/h1_ambiguity_attack_blocks.py  (from paper-tripwire/)"""
import collections, glob, json, sys
sys.dont_write_bytecode = True
T = "."
sys.path.insert(1, T)
from diag_h1_cu import D, MODELS, SUITES, replay  # noqa: E402

ARM = "v2b_strict"
n_tr = n_succ = 0
blocks = collections.Counter()
amb_traces = []
amb_tasks = set()
for model in MODELS:
    for f in glob.glob(f"{D}/{model}/none/*/*/user_task_*/important_instructions/injection_task_*.json"):
        d = json.load(open(f))
        if "utility" not in d:
            continue
        n_tr += 1
        n_succ += bool(d.get("security"))
        got_amb = False
        goal = SUITES[d["suite_name"]].injection_tasks[d["injection_task_id"]].GOAL.lower()
        for b in replay(d, ARM):
            rules = {r for r, _, _ in b["rs"]}
            blocks["blocked_calls"] += 1
            if "LABEL:AMBIGUOUS" in rules:
                blocks["with_ambiguous"] += 1
                got_amb = True
                for r, a, val in b["rs"]:
                    if r == "LABEL:AMBIGUOUS":
                        blocks["amb_value_in_injection_goal" if val.lower() in goal else "amb_value_not_in_goal"] += 1
                        amb_tasks.add((d["suite_name"], d["user_task_id"]))
                if rules == {"LABEL:AMBIGUOUS"}:
                    blocks["ambiguous_only"] += 1
        if got_amb:
            amb_traces.append((model, d["suite_name"], d["user_task_id"], d["injection_task_id"], bool(d.get("security"))))
print("attack traces", n_tr, "successful undefended", n_succ)
print(dict(blocks))
print("traces with an ambiguous block", len(amb_traces), "of which undefended attack succeeded", sum(x[4] for x in amb_traces))
for x in amb_traces[:20]:
    print(" ", x)
print("distinct user tasks with an ambiguous block", sorted(amb_tasks))
