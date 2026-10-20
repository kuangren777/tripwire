import pytest

import llm_env


def test_reads_environment(monkeypatch):
    monkeypatch.setenv("LLM_API_BASE", "https://example.invalid/v1/")
    monkeypatch.setenv("LLM_API_KEY", "k")
    assert llm_env.api_base() == "https://example.invalid/v1"
    assert llm_env.api_key() == "k"


def test_missing_values_stop(monkeypatch):
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        llm_env.api_base()
    with pytest.raises(SystemExit):
        llm_env.api_key()
