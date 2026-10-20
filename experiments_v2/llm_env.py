"""Endpoint and key for the hosted agent models, read from the environment at call time.

LLM_API_BASE: an OpenAI-compatible base URL including the /v1 suffix.
LLM_API_KEY: the key for that endpoint.
"""
import os


def api_base():
    base = os.environ.get("LLM_API_BASE", "").strip()
    if not base:
        raise SystemExit("set LLM_API_BASE to an OpenAI-compatible base URL (with /v1)")
    return base.rstrip("/")


def api_key():
    key = os.environ.get("LLM_API_KEY", "").strip()
    if not key:
        raise SystemExit("set LLM_API_KEY")
    return key
