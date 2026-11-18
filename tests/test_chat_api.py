import json
import random
import urllib.error

import pytest

from sastlab.llm import SoCLaaS, model_from
from sastlab.runner import load_config


def reply(content='{"operator":"rename"}', tokens=100, finish="stop"):
    return {"choices": [{"message": {"content": content}, "finish_reason": finish}],
            "usage": {"prompt_tokens": tokens}}


def test_credentials_and_exact_request_audit(tmp_path, monkeypatch):
    monkeypatch.delenv("SAST_TEST_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text('export SAST_TEST_KEY="secret-test-value"\n')
    llm = SoCLaaS("http://example.invalid/v1", api_key_env="SAST_TEST_KEY", env_file=env)
    captured = []
    def request(endpoint, payload=None):
        if endpoint == "/models":
            return {"data": [{"id": "llama3.1:8b"}]}
        captured.append((endpoint, payload))
        return reply()
    llm.request = request
    assert llm.choose({}, ["rename"], random.Random(1), 6224) == "rename"
    endpoint, payload = captured[0]
    assert endpoint == "/chat/completions"
    assert payload == llm.audit[0]["request"]
    assert payload["seed"] == 6224 and payload["temperature"] == 0.2
    assert payload["response_format"]["json_schema"]["strict"]
    assert "secret-test-value" not in json.dumps(llm.audit + [llm.identity()])
    assert llm.identity()["identity_verified"] is False


@pytest.mark.parametrize("response", [reply(tokens=2501), reply(tokens=None), reply(finish="length"),
    reply('{"operator":"not_available"}'), reply('{"ranking":["rename","rename"]}')])
def test_invalid_response_retries_and_falls_back(monkeypatch, response):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS("http://example.invalid/v1")
    llm.request = lambda *args: response
    assert llm.choose({}, ["rename"], random.Random(1), 1) == "rename"
    assert len(llm.audit) == 4 and llm.audit[-1]["fallback"]


def test_ranking_and_environment_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "environment-secret")
    llm = SoCLaaS("http://example.invalid/v1", env_file=tmp_path / "missing")
    assert llm._api_key == "environment-secret"
    llm.request = lambda *args: reply('{"ranking":["format_swap","rename"]}')
    assert llm.choose({}, ["rename", "format_swap"], random.Random(1), 1, ranking=True) == ["format_swap", "rename"]
    assert not llm.audit[-1]["fallback"]


def test_http_error_does_not_log_server_secrets(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "secret-test-value")
    llm = SoCLaaS("http://example.invalid/v1")
    class Opener:
        def open(self, request, timeout):
            assert request.get_header("Authorization") == "Bearer secret-test-value"
            raise urllib.error.HTTPError(request.full_url, 401, "secret-test-value", {}, None)
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener())
    llm.choose({}, ["rename"], random.Random(1), 1)
    assert "secret-test-value" not in json.dumps(llm.audit)
    assert "HTTP status 401" in llm.audit[0]["error"]


def test_config_resolves_env_file(monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    root = Path(__file__).resolve().parents[1]
    config = load_config(root / "configs/semgrep.json")
    assert config["llm"]["env_file"] == str(root / ".env")
    assert isinstance(model_from(config), SoCLaaS)
    assert "test-value" not in json.dumps(config)


def test_identity_requires_model_to_be_served(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS("http://example.invalid/v1")
    llm.request = lambda endpoint, payload=None: {"data": [{"id": "other-model"}]}
    with pytest.raises(ValueError, match="not available"):
        llm.identity()


class _Reply:
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, *args): return json.dumps(self.data).encode()


def _opener(outcomes):
    outcomes = iter(outcomes)
    class Opener:
        def open(self, request, timeout):
            outcome = next(outcomes)
            if isinstance(outcome, int):
                import email.message
                headers = email.message.Message()
                if outcome == 429 and Opener.retry_after is not None:
                    headers["Retry-After"] = Opener.retry_after
                raise urllib.error.HTTPError(request.full_url, outcome, "limited", headers, None)
            return _Reply(outcome)
    Opener.retry_after = None
    return Opener


def test_rate_limit_waits_then_succeeds_without_using_validation_retries(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS("http://example.invalid/v1", backoff_base=2, backoff_cap=60)
    sleeps = []
    llm._sleep = sleeps.append
    Opener = _opener([429, 429, 429, reply()])
    Opener.retry_after = "7"
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener())
    assert llm.choose({}, ["rename"], random.Random(1), 1) == "rename"
    assert sleeps == [7.0, 7.0, 7.0]
    assert len(llm.audit) == 1 and not llm.audit[0]["fallback"] and llm.audit[0]["retry"] == 0
    assert llm.audit[0]["rate_limit_waits"] == [7.0, 7.0, 7.0]


def test_rate_limit_backoff_is_exponential_and_capped_without_retry_after(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS("http://example.invalid/v1", backoff_base=10, backoff_cap=30)
    sleeps = []
    llm._sleep = sleeps.append
    opener = _opener([429, 429, 429, 429, reply()])()
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: opener)
    assert llm.choose({}, ["rename"], random.Random(1), 1) == "rename"
    assert sleeps == [10, 20, 30, 30]


def test_persistent_rate_limit_eventually_falls_back(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS("http://example.invalid/v1", max_rate_limit_retries=2)
    llm._sleep = lambda seconds: None
    opener = _opener([429] * 9)()
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: opener)
    assert llm.choose({}, ["rename"], random.Random(1), 1) == "rename"
    assert llm.audit[-1]["fallback"] and "429" in llm.audit[0]["error"]


def test_min_interval_spaces_requests(monkeypatch):
    monkeypatch.setenv("SOCLAAS_API_KEY", "test-value")
    llm = SoCLaaS("http://example.invalid/v1", min_interval=5)
    sleeps = []
    llm._sleep = sleeps.append
    opener = _opener([reply(), reply()])()
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: opener)
    llm.choose({}, ["rename"], random.Random(1), 1)
    llm.choose({}, ["rename"], random.Random(1), 2)
    assert len(sleeps) == 1 and 4 < sleeps[0] <= 5
