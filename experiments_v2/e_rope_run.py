"""E1/E2/E4 driver (EXPERIMENT_PLAN_rope.md). Runs every arm inside ROPE's official harness (agent-fuzz/ext/rope @ 64495e16):
ROPE's AgentDojo v1.2.2 suites, benchmark functions, attack loader and logging. Only two things are ours:
the agent LLM client goes to camel-hub (or the shared vLLM on 8021 for qwen3-8b-local) instead of OpenRouter, and
the tripwire / tripwire_strict arms build ROPE's passthrough pipeline shape with TripWireExecutor as the executor.
usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 e_rope_run.py --model M --arm none|rope|tripwire|tripwire_strict
           --suite banking|slack|travel --attack none|important_instructions [--user-task ..] [--injection-task ..]"""
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

VERSION = "v1.2.2"
HUB = "https://api.camel-hub.cn/v1"
LOCAL = {"qwen3-8b-local": ("http://127.0.0.1:8021/v1", "qwen3-8b-local")}   # served name on the shared vLLM, as in testbed/harness.py
# Attack text names the model from the pipeline name (agentdojo.attacks.base_attacks.get_model_name_from_pipeline):
# gpt-4o-mini-2024-07-18 -> "GPT-4", every other model here -> "AI assistant", exactly as in ROPE's own runs.


def hub_key():
    """The agent gateway key: set CAMEL_HUB_KEY (or point CAMEL_HUB_ENV at a file defining it)."""
    if os.environ.get("CAMEL_HUB_KEY"):
        return os.environ["CAMEL_HUB_KEY"]
    p = os.environ.get("CAMEL_HUB_ENV", "")
    if p and os.path.exists(p):
        for line in open(p):
            if line.startswith("CAMEL_HUB_KEY="):
                return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("set CAMEL_HUB_KEY (see README)")


def agent_llm(model, temperature):
    if model in LOCAL:
        url, served = LOCAL[model]
        return OpenAILLM(openai.OpenAI(api_key="EMPTY", base_url=url), served, temperature=temperature)
    return OpenAILLM(openai.OpenAI(api_key=hub_key(), base_url=HUB), model, temperature=temperature)


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
    if arm in ("tripwire", "tripwire_strict"):
        tw = TripWireExecutor(mode="block" if arm == "tripwire" else "strict")
        pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), ResetTW(tw), llm,
                              ToolsExecutionLoop([tw, llm])])
        pipe.name = name
        return pipe
    if arm in ("tripwire_v2", "tripwire_strict_v2"):   # v2b_deleg / v2b_strict in tripwire_v2.ARMS
        from tripwire_v2 import ARMS, TripWireV2
        tw = TripWireV2(**ARMS["v2b_deleg" if arm == "tripwire_v2" else "v2b_strict"])
        pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), ResetTW(tw), llm,
                              ToolsExecutionLoop([tw, llm])])
        pipe.name = name
        return pipe
    raise SystemExit(f"unknown arm {arm}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--arm", required=True)
    ap.add_argument("--suite", required=True, choices=["banking", "slack", "travel", "shopping", "github", "dailylife"])
    ap.add_argument("--attack", default="none")
    ap.add_argument("--user-task", action="append", default=None)
    ap.add_argument("--injection-task", action="append", default=None)
    ap.add_argument("--logdir", type=Path, default=Path("./data/e1_rope"))
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
