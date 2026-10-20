"""E1/E2/E4 driver (EXPERIMENT_PLAN_rope.md). Runs every arm inside ROPE's official harness (agent-fuzz/ext/rope @ 64495e16):
ROPE's AgentDojo v1.2.2 suites, benchmark functions, attack loader and logging. Only two things are ours:
the agent LLM client goes to an OpenAI-compatible API endpoint (or the shared vLLM on 8021 for qwen3-8b-local) instead of OpenRouter, and
the tripwire / tripwire_strict arms build ROPE's passthrough pipeline shape with TripWireExecutor as the executor.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 e_rope_run.py --model M --arm none|rope|tripwire|tripwire_strict
           --suite banking|slack|travel --attack none|important_instructions [--user-task ..] [--injection-task ..]"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import argparse
import os
import sys
from pathlib import Path

import openai

sys.path.insert(1, ".")
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections  # noqa: E402
from agentdojo.logging import OutputLogger  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from rope import pipeline as RP  # noqa: E402
from rope.scopes_io import load_router_scopes  # noqa: E402
from tripwire import TripWireExecutor  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import llm_env  # noqa: E402  LLM_API_BASE / LLM_API_KEY, read at call time

VERSION = "v1.2.2"
LOCAL = {"qwen3-8b-local": ("http://localhost:8021/v1", "qwen3-8b-local")}   # served name on the shared vLLM, as in testbed/harness.py
# Attack text names the model from the pipeline name (agentdojo.attacks.base_attacks.get_model_name_from_pipeline):
# gpt-4o-mini-2024-07-18 -> "GPT-4", every other model here -> "AI assistant", exactly as in ROPE's own runs.


def agent_llm(model, temperature):
    if model in LOCAL:
        url, served = LOCAL[model]
        return OpenAILLM(openai.OpenAI(api_key="EMPTY", base_url=url), served, temperature=temperature)
    return OpenAILLM(openai.OpenAI(api_key=llm_env.api_key(), base_url=llm_env.api_base()), model, temperature=temperature)


class ResetTW(BasePipelineElement):
    """ROPE's benchmark loop reuses one pipeline object across tasks; TripWire's provenance index must start empty
    for each task (in TripWire's own harness a fresh executor is built per task)."""
    def __init__(self, tw):
        self.tw = tw

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        self.tw.prov, self.tw.flags, self.tw.calls = None, [], []
        return query, runtime, env, messages, extra_args or {}


def build(arm, suite, llm, name):
    if arm == "none":
        return RP.build_passthrough_pipeline(llm, name=name)
    if arm == "rope":
        floor, scopes = load_router_scopes("opus", suite)
        return RP.build_routed_pipeline(llm, suite_name=suite, floor=floor, cached_scopes=scopes, name=name)
    if arm == "rope_fixed":   # Amendment 7 (R2c): same ROPE pipeline, router output removed (no overrides, no named source)
        from rope.policy_synthesis import TaskScope
        floor, scopes = load_router_scopes("opus", suite)
        fixed = {p: TaskScope(bucket=sc.bucket, named_source=None, overrides={}) for p, sc in scopes.items()}
        return RP.build_routed_pipeline(llm, suite_name=suite, floor=floor, cached_scopes=fixed, name=name)
    if arm in ("tripwire", "tripwire_strict"):
        tw = TripWireExecutor(mode="block" if arm == "tripwire" else "strict")
        pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), ResetTW(tw), llm,
                              ToolsExecutionLoop([tw, llm])])
        pipe.name = name
        return pipe
    if arm in ("tripwire_v2", "tripwire_strict_v2", "tripwire_strict_v21"):   # v2b_deleg / v2b_strict / v21_strict
        from tripwire_v2 import ARMS, TripWireV2
        tw = TripWireV2(**ARMS[{"tripwire_v2": "v2b_deleg", "tripwire_strict_v2": "v2b_strict",
                                "tripwire_strict_v21": "v21_strict"}[arm]])
        pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), ResetTW(tw), llm,
                              ToolsExecutionLoop([tw, llm])])
        pipe.name = name
        return pipe
    if arm == "tripwire_strict_v2_oracle":   # Amendment 8: v2b_strict plus oracle USER source
        from tripwire_v2 import ARMS, TripWireV2
        tw = OracleStrict(oracle_values(suite), **ARMS["v2b_strict"])
        pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), ResetTW(tw), llm,
                              ToolsExecutionLoop([tw, llm])])
        pipe.name = name
        return pipe
    raise SystemExit(f"unknown arm {arm}")


def oracle_values(sn):
    """Amendment 8: prompt -> census-synthesized ground-truth control values of that task (the RQ3 census rule of
    boundary_prevalence.py / scripts/h1_synthesis_split.py: length >= 3, absent from the prompt and the clean env)."""
    from boundary_prevalence import CONTROL_ALL, env_text
    suite = get_suite(VERSION, sn)
    env = suite.load_and_inject_default_environment({})
    E = env_text(env)
    out = {}
    for t in suite.user_tasks.values():
        p = t.PROMPT.lower()
        try:
            gt = t.ground_truth(env)
        except Exception:  # noqa: BLE001
            continue
        vs = []
        for c in gt:
            for a in CONTROL_ALL.get(c.function, ()):
                v = c.args.get(a)
                for x in (v if isinstance(v, (list, tuple)) else [v]):
                    x = str(x)
                    if len(x) >= 3 and x.lower() not in p and x.lower() not in E and x not in vs:
                        vs.append(x)
        if vs:
            out[t.PROMPT.strip()] = vs
    return out


def OracleStrict(oracle, **kw):
    """v2b_strict whose provenance index also counts the task's oracle values as USER text. The model's prompt and
    every other rule are unchanged; only the provenance built at the first tool call sees the extra values."""
    from tripwire_v2 import ProvenanceV2, TripWireV2

    class _Oracle(TripWireV2):
        def query(self, query, runtime, env, messages=(), extra_args={}):
            if self.prov is None:
                extra = oracle.get(query.strip(), [])
                self.prov = ProvenanceV2(query + "".join("\n" + x for x in extra), self.use_compact, self.use_taint,
                                         self.amb)
                self.prov.history, self.prov.v2c, self.prov.expand_lists = self.history, self.v2c, self.expand_lists
                self.oracle_used = list(extra)
            return super().query(query, runtime, env, messages, extra_args)

    return _Oracle(**kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--arm", required=True)
    ap.add_argument("--suite", required=True, choices=["banking", "slack", "travel", "shopping", "github", "dailylife"])
    ap.add_argument("--attack", default="none")
    ap.add_argument("--user-task", action="append", default=None)
    ap.add_argument("--injection-task", action="append", default=None)
    ap.add_argument("--logdir", type=Path, default=Path("./data_v2/e1_rope"))
    ap.add_argument("--temperature", type=float, default=0.0)
    a = ap.parse_args()
    name = f"{a.model}-{a.arm}"
    logdir = a.logdir / a.model / a.arm
    logdir.mkdir(parents=True, exist_ok=True)
    pipe = build(a.arm, a.suite, agent_llm(a.model, a.temperature), name)
    suite = get_suite(VERSION, a.suite)
    print(f"pipeline {pipe.name} suite={a.suite} attack={a.attack}", flush=True)
    with OutputLogger(str(logdir), live=None):
        if a.attack == "none":
            r = benchmark_suite_without_injections(pipe, suite, user_tasks=a.user_task, logdir=logdir,
                                                   force_rerun=False, benchmark_version=VERSION)
        else:
            r = benchmark_suite_with_injections(pipe, suite, load_attack(a.attack, suite, pipe), user_tasks=a.user_task,
                                                injection_tasks=a.injection_task, logdir=logdir, force_rerun=False,
                                                benchmark_version=VERSION)
    u = list(r["utility_results"].values())
    print(f"[{a.model} {a.arm} {a.suite} {a.attack}] utility {sum(u)}/{len(u)}", flush=True)
    if a.attack != "none":
        s = list(r["security_results"].values())
        print(f"[{a.model} {a.arm} {a.suite} {a.attack}] ASR {sum(s)}/{len(s)}", flush=True)


if __name__ == "__main__":
    main()
