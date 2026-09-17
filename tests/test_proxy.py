"""Интеграция прокси: маскирование запроса, восстановление ответа, detect,
fail-closed, entities-заголовок, правила, аудит, метрики. Апстрим — мок."""
import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient, MockTransport

from compass_llm_filter.proxy.app import create_app
from compass_llm_filter.proxy.config import Settings

PHONE = "+7 912 345-67-89"
COMPANY = "ООО Ромашка"


def make_settings(**kw) -> Settings:
    base = dict(upstream_base_url="http://upstream.test", audit_max_entries=10)
    base.update(kw)
    return Settings(**base)


def echo_upstream(seen: list):
    """Фейковый LLM: отвечает эхом последнего пользовательского сообщения."""
    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append({
            "body": json.loads(request.content) if request.content else None,
            "headers": dict(request.headers),
            "path": request.url.path,
        })
        payload = json.loads(request.content)
        last_user = next((m["content"] for m in reversed(payload.get("messages", []))
                          if m["role"] == "user"), "")
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": f"Эхо: {last_user}"}}],
            "model": payload.get("model"),
        })
    return MockTransport(handler)


def make_client(settings: Settings, seen: list) -> AsyncClient:
    app = create_app(settings, upstream_transport=echo_upstream(seen))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://compass.test")


def chat_payload(text: str) -> dict:
    return {"model": "glm-5.2", "messages": [{"role": "user", "content": text}]}


@pytest.mark.asyncio
async def test_request_masked_upstream_response_restored():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.post("/chat/completions", json=chat_payload(
            f"перезвоните {PHONE} или напишите ivan.ivanov@romashka.ru"))
    assert resp.status_code == 200
    sent = seen[0]["body"]["messages"][0]["content"]
    assert PHONE not in sent and "romashka.ru" not in sent   # провайдер не видел
    assert "Эхо:" in resp.json()["choices"][0]["message"]["content"]
    assert PHONE in resp.text and "romashka.ru" in resp.text  # клиент получил оригиналы


@pytest.mark.asyncio
async def test_entities_header_registered_and_stripped():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.post("/chat/completions", json=chat_payload(
            "Напомните клиенту ООО Ромашка про оплату"),
            headers={"X-Compass-Entities": json.dumps([COMPANY])})
    assert resp.status_code == 200
    sent = seen[0]["body"]["messages"][0]["content"]
    assert "Ромашка" not in sent                            # зарегистрированная сущность замаскирована
    assert "x-compass-entities" not in seen[0]["headers"]     # заголовок наверх не ушёл
    assert "Ромашка" in resp.text                           # и восстановлена в ответе


@pytest.mark.asyncio
async def test_malformed_entities_header_400_fail_closed():
    seen = []
    async with make_client(make_settings(), seen) as client:
        resp = await client.post("/chat/completions", json=chat_payload("текст"),
                                 headers={"X-Compass-Entities": "{not json"})
    assert resp.status_code == 400
    assert seen == []                                       # наверх не ходили


@pytest.mark.asyncio
async def test_detect_mode_forwards_original():
    seen = []
    async with make_client(make_settings(mode="detect"), seen) as client:
        resp = await client.post("/chat/completions", json=chat_payload(f"телефон {PHONE}"))
    assert resp.status_code == 200
    assert PHONE in seen[0]["body"]["messages"][0]["content"]   # провайдеру ушёл оригинал
    assert PHONE in resp.text                                   # и вернулся как есть


@pytest.mark.asyncio
async def test_fail_closed_on_masking_error():
    seen = []
    settings = make_settings()

    import compass_llm_filter.proxy.app as app_mod

    app = create_app(settings, upstream_transport=echo_upstream(seen))
    original = app_mod.Anonymizer

    class Broken(original):
        def sanitize_string(self, s):
            raise RuntimeError("boom")

    app_mod.Anonymizer = Broken
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://m") as client:
            resp = await client.post("/chat/completions", json=chat_payload("текст"))
            assert resp.status_code == 503                      # наружу ничего не ушло
            assert seen == []
            # fail-open: тот же сбой пропускает трафик
            app.state.compass.fail_mode = "open"
            resp = await client.post("/chat/completions", json=chat_payload("текст"))
            assert resp.status_code == 200
            assert len(seen) == 1
    finally:
        app_mod.Anonymizer = original


@pytest.mark.asyncio
async def test_settings_api_switch_mode_live():
    seen = []
    async with make_client(make_settings(), seen) as client:
        assert (await client.get("/v1/settings")).json()["mode"] == "enforce"
        await client.put("/v1/settings", json={"mode": "detect"})
        await client.post("/chat/completions", json=chat_payload(f"тел {PHONE}"))
        assert PHONE in seen[0]["body"]["messages"][0]["content"]  # без рестарта
        bad = await client.put("/v1/settings", json={"mode": "yolo"})
        assert bad.status_code == 400


@pytest.mark.asyncio
async def test_custom_rule_full_cycle():
    seen = []
    async with make_client(make_settings(), seen) as client:
        created = await client.post("/v1/rules", json={
            "name": "internal order id", "pattern": r"ORD-\d{6}", "replacement": "fake"})
        assert created.status_code == 200
        rule_id = created.json()["id"]
        resp = await client.post("/chat/completions", json=chat_payload(
            "заказ ORD-123456 не отображается"))
        assert resp.status_code == 200
        sent = seen[0]["body"]["messages"][0]["content"]
        assert "ORD-123456" not in sent and "ORD-" in sent      # фейк той же формы
        assert "ORD-123456" in resp.text                        # восстановлен
        # выключение правила — больше не маскируется
        await client.patch(f"/v1/rules/{rule_id}", json={"enabled": False})
        await client.post("/chat/completions", json=chat_payload("заказ ORD-654321"))
        assert "ORD-654321" in seen[1]["body"]["messages"][0]["content"]
        assert (await client.delete(f"/v1/rules/{rule_id}")).status_code == 200


@pytest.mark.asyncio
async def test_invalid_rule_regex_400():
    async with make_client(make_settings(), []) as client:
        resp = await client.post("/v1/rules", json={"pattern": "("})
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_audit_records_written():
    seen = []
    async with make_client(make_settings(), seen) as client:
        await client.post("/chat/completions", json=chat_payload(f"тел {PHONE}"))
        records = (await client.get("/v1/audit/records")).json()["records"]
        assert records and records[-1]["detected"].get("phones") == 1
        assert records[-1]["mode"] == "enforce"


@pytest.mark.asyncio
async def test_metrics_prometheus_text():
    async with make_client(make_settings(), []) as client:
        await client.post("/chat/completions", json=chat_payload(f"тел {PHONE}"))
        body = (await client.get("/metrics")).text
        assert "compass_masked_total" in body
        assert 'type="phones"' in body


@pytest.mark.asyncio
async def test_healthz():
    async with make_client(make_settings(), []) as client:
        data = (await client.get("/healthz")).json()
        assert data["status"] == "ok" and data["upstream"] == "http://upstream.test"


@pytest.mark.asyncio
async def test_non_json_body_passthrough():
    seen = []

    def raw_transport():
        async def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.content)
            return httpx.Response(200, content=b"pong", headers={"content-type": "text/plain"})
        return MockTransport(handler)

    settings = make_settings()
    app = create_app(settings, upstream_transport=raw_transport())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://m") as client:
        resp = await client.post("/embeddings", content=b"\x00\x01binary",
                                 headers={"content-type": "application/octet-stream"})
    assert resp.status_code == 200 and resp.content == b"pong"
    assert seen[0] == b"\x00\x01binary"                        # не тронуто


@pytest.mark.asyncio
async def test_sandbox_endpoint():
    async with make_client(make_settings(), []) as client:
        resp = await client.post("/v1/sandbox", json={
            "text": f"Клиент {COMPANY}, тел {PHONE}", "entities": [COMPANY]})
        data = resp.json()
        assert COMPANY not in data["masked"] and PHONE not in data["masked"]
        assert data["leaks"] == 0
        assert COMPANY in data["restored"]


@pytest.mark.asyncio
async def test_upstream_error_502():
    def failing():
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")
        return MockTransport(handler)

    app = create_app(make_settings(), upstream_transport=failing())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://m") as client:
        resp = await client.post("/chat/completions", json=chat_payload("текст"))
    assert resp.status_code == 502


@pytest.mark.asyncio
async def test_deterministic_fakes_across_requests():
    seen = []
    async with make_client(make_settings(), seen) as client:
        await client.post("/chat/completions", json=chat_payload(f"тел {PHONE}"))
        await client.post("/chat/completions", json=chat_payload(f"тел {PHONE}"))
    first = seen[0]["body"]["messages"][0]["content"]
    second = seen[1]["body"]["messages"][0]["content"]
    assert first == second                                    # один вход — один фейк


@pytest.mark.asyncio
async def test_entities_header_raw_utf8_bytes_recovered():
    # curl шлёт кириллицу в заголовке сырыми UTF-8 байтами; ASGI отдаёт latin-1.
    # Прокси обязан восстановить (регресс: «ООО Ромашка» уезжала моджибейком).
    seen = []
    async with make_client(make_settings(), seen) as client:
        raw_utf8 = json.dumps([COMPANY], ensure_ascii=False).encode("utf-8")
        resp = await client.post("/chat/completions", json=chat_payload(
            f"Клиент {COMPANY} снова тут"), headers={"X-Compass-Entities": raw_utf8})
    assert resp.status_code == 200
    sent = seen[0]["body"]["messages"][0]["content"]
    assert "Ромашка" not in sent
    assert "Ромашка" in resp.text
