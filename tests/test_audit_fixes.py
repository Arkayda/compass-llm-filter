"""Регрессии аудита интеграции 2026-09 (граница компаса).

Закрывают обходы маскирования:
- В2: JSON глубже MAX_RECURSION_DEPTH уходил апстриму незамаскированным
  (и leak-check его не видел);
- В3: тело с битым/не-JSON контентом проходило в enforce+fail-closed без
  записи в аудит;
- В4: тела DELETE/GET/HEAD не маскировались вовсе; ReDoS-валидатор правил
  не видел паттерны, взрывающиеся на смешанных алфавитах (((a|a)b)+c).
"""
import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient, MockTransport

from compass_llm_filter.proxy.app import create_app
from compass_llm_filter.proxy.config import Settings
from compass_llm_filter.proxy.rules import validate_safe_regex

PHONE = "+7 912 345-67-89"


def make_settings(**kw) -> Settings:
    base = dict(upstream_base_url="http://upstream.test", audit_max_entries=10)
    base.update(kw)
    return Settings(**base)


def raw_upstream(seen: list, reply_json: bool = True):
    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append({
            "content": request.content,
            "path": request.url.path,
            "method": request.method,
        })
        if reply_json:
            payload = json.loads(request.content)
            last_user = next((m.get("content", "") for m in reversed(payload.get("messages", []))
                              if m.get("role") == "user"), "")
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": f"Эхо: {last_user}"}}],
            })
        return httpx.Response(200, content=b"pong",
                              headers={"content-type": "text/plain"})
    return MockTransport(handler)


def make_client(settings: Settings, seen: list, reply_json: bool = True) -> AsyncClient:
    app = create_app(settings, upstream_transport=raw_upstream(seen, reply_json))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://compass.test")


def _deep(obj, levels: int) -> dict:
    for _ in range(levels):
        obj = {"n": obj}
    return obj


# ── В2: глубокий JSON ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deep_json_pii_blocked_in_enforce_closed():
    seen = []
    async with make_client(make_settings(), seen) as client:
        deep = _deep({"messages": [{"role": "user", "content": f"тел {PHONE}"}]}, 40)
        resp = await client.post("/chat/completions", json=deep)
    assert resp.status_code == 503, "глубже лимита маскирования = блок в enforce+closed"
    assert seen == [], "апстрим не должен получить незамаскированное тело"


@pytest.mark.asyncio
async def test_deep_json_audited_in_detect():
    seen = []
    async with make_client(make_settings(mode="detect"), seen) as client:
        deep = _deep({"messages": [{"role": "user", "content": f"тел {PHONE}"}]}, 40)
        resp = await client.post("/chat/completions", json=deep)
        records = (await client.get("/v1/audit/records")).json()["records"]
    assert resp.status_code == 200
    assert PHONE.encode() in seen[0]["content"], "detect пропускает оригинал"
    assert any("depth" in (r.get("reason") or "") for r in records), (
        "passthrough глубины обязан попадать в аудит с понятной причиной"
    )


@pytest.mark.asyncio
async def test_shallow_json_still_masked():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.post("/chat/completions", json={
            "messages": [{"role": "user", "content": f"тел {PHONE}"}]})
    assert resp.status_code == 200
    assert PHONE.encode() not in seen[0]["content"]


# ── В3: битый / не-JSON body ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_broken_json_body_blocked_in_enforce_closed():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.post(
            "/chat/completions", content=f"текст без JSON, тел {PHONE}".encode(),
            headers={"content-type": "application/json"})
    assert resp.status_code == 503, "объявлен JSON, но не парсится — маскировать нельзя"
    assert seen == []


@pytest.mark.asyncio
async def test_binary_body_blocked_in_enforce_closed():
    seen = []
    async with make_client(make_settings(), seen, reply_json=False) as client:
        resp = await client.post(
            "/embeddings", content=b"\x00\x01binary",
            headers={"content-type": "application/octet-stream"})
    assert resp.status_code == 503, (
        "enforce+closed: не смогли гарантированно замаскировать — блокируем "
        "(та же политика, что и для сжатых тел)"
    )
    assert seen == []


@pytest.mark.asyncio
async def test_binary_body_passthrough_audited_in_detect():
    seen = []
    async with make_client(make_settings(mode="detect"), seen, reply_json=False) as client:
        resp = await client.post(
            "/embeddings", content=b"\x00\x01binary",
            headers={"content-type": "application/octet-stream"})
        records = (await client.get("/v1/audit/records")).json()["records"]
    assert resp.status_code == 200 and resp.content == b"pong"
    assert seen[0]["content"] == b"\x00\x01binary"
    assert any("non-JSON" in (r.get("reason") or "") or "json" in (r.get("reason") or "").lower()
               for r in records), "passthrough не-JSON тела должен быть в аудите"


# ── В4: тела любых методов + ReDoS-зонды ────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_body_masked():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.request(
            "DELETE", "/v1/files/file-1", json={"reason": f"удалить, тел {PHONE}"})
    assert resp.status_code == 200
    assert PHONE.encode() not in seen[0]["content"], "тело DELETE тоже обязано маскироваться"


@pytest.mark.asyncio
async def test_get_body_masked():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.request(
            "GET", "/v1/search", json={"q": f"тел {PHONE}"})
    assert resp.status_code == 200
    assert PHONE.encode() not in seen[0]["content"]


def test_redos_mixed_alphabet_rejected():
    with pytest.raises(ValueError):
        validate_safe_regex(r"((a|a)b)+c")


def test_redos_normal_pattern_still_accepted():
    validate_safe_regex(r"ORD-\d{4,8}")          # не должен бросать
    validate_safe_regex(r"\b\w+@\w+\.\w{2,}\b")  # не должен бросать
