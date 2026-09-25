"""Политика скорости: принудительное отключение thinking для быстрых моделей.

GLM через Anthropic-совместимый API думает ПО УМОЛЧАНИЮ: замер 2026-09-25 —
голый вызов 6.1с с thinking против 2.3с без; в ответах агента 90% генерации —
размышления (3472 символов thinking на 385 символов текста). Для скоростных
моделей компас принудительно ставит thinking:disabled, если вызывающий не
попросил thinking явно.
"""
import json

import httpx
from httpx import ASGITransport, AsyncClient, MockTransport

from compass_llm_filter.proxy.app import create_app
from compass_llm_filter.proxy.config import Settings


def make_settings(**kw) -> Settings:
    base = dict(upstream_base_url="http://upstream.test", audit_max_entries=10)
    base.update(kw)
    return Settings(**base)


def echo_upstream(seen: list):
    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "msg_1", "role": "assistant",
            "content": [{"type": "text", "text": "ок"}],
        })
    return MockTransport(handler)


def make_client(settings: Settings, seen: list) -> AsyncClient:
    app = create_app(settings, upstream_transport=echo_upstream(seen))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://compass.test")


def body(model: str, thinking=None) -> dict:
    b = {"model": model, "max_tokens": 64,
         "messages": [{"role": "user", "content": "вопрос"}]}
    if thinking is not None:
        b["thinking"] = thinking
    return b


async def post(client: AsyncClient, b: dict) -> httpx.Response:
    return await client.post("/api/anthropic/v1/messages", json=b)


async def test_flash_model_gets_thinking_disabled():
    seen = []
    async with make_client(make_settings(disable_thinking_models="glm-5.3-flash"), seen) as c:
        r = await post(c, body("glm-5.3-flash"))
    assert r.status_code == 200
    assert seen[0].get("thinking") == {"type": "disabled"}


async def test_other_model_untouched():
    seen = []
    async with make_client(make_settings(disable_thinking_models="glm-5.3-flash"), seen) as c:
        r = await post(c, body("glm-5.2[1m]"))
    assert r.status_code == 200
    assert "thinking" not in seen[0]


async def test_claude_code_adaptive_thinking_overridden():
    """claude-code шлёт thinking:{"type":"adaptive"} — для скоростной модели
    его надо перезаписывать, иначе GLM думает (регрессия 2026-09-25: политика
    «уважать явный thinking» пропускала adaptive и молчала)."""
    seen = []
    async with make_client(make_settings(disable_thinking_models="glm-5.3-flash"), seen) as c:
        r = await post(c, body("glm-5.3-flash",
                               thinking={"type": "adaptive", "display": "omitted"}))
    assert r.status_code == 200
    assert seen[0]["thinking"] == {"type": "disabled"}


async def test_explicit_thinking_respected_off_list():
    seen = []
    async with make_client(make_settings(disable_thinking_models="glm-5.3-flash"), seen) as c:
        r = await post(c, body("glm-5.2[1m]",
                               thinking={"type": "enabled", "budget_tokens": 1024}))
    assert r.status_code == 200
    assert seen[0]["thinking"] == {"type": "enabled", "budget_tokens": 1024}


async def test_empty_policy_list_is_noop():
    seen = []
    async with make_client(make_settings(disable_thinking_models=""), seen) as c:
        r = await post(c, body("glm-5.3-flash"))
    assert r.status_code == 200
    assert "thinking" not in seen[0]


def test_from_env_default_applies_when_env_unset(monkeypatch):
    """Регрессия: from_env перебивал дефолт поля пустой строкой — политика
    работала в юнит-тестах (Settings(**kw)) и молчала в живом приложении."""
    from compass_llm_filter.proxy.config import Settings
    monkeypatch.delenv("COMPASS_DISABLE_THINKING_MODELS", raising=False)
    monkeypatch.setenv("COMPASS_UPSTREAM_BASE_URL", "https://api.example")
    monkeypatch.delenv("COMPASS_MODE", raising=False)
    monkeypatch.delenv("COMPASS_FAIL_MODE", raising=False)
    s = Settings.from_env()
    assert "glm-5.3-flash" in s.disable_thinking_models


def test_from_env_env_overrides_default(monkeypatch):
    from compass_llm_filter.proxy.config import Settings
    monkeypatch.setenv("COMPASS_UPSTREAM_BASE_URL", "https://api.example")
    monkeypatch.setenv("COMPASS_DISABLE_THINKING_MODELS", "other-model, third ")
    monkeypatch.delenv("COMPASS_MODE", raising=False)
    monkeypatch.delenv("COMPASS_FAIL_MODE", raising=False)
    s = Settings.from_env()
    assert s.disable_thinking_models == "other-model, third "


async def test_comma_separated_list_and_metrics():
    seen = []
    async with make_client(
        make_settings(disable_thinking_models=" glm-5.3-flash , other-fast "), seen
    ) as c:
        r = await post(c, body("other-fast"))
    assert r.status_code == 200
    assert seen[0].get("thinking") == {"type": "disabled"}
