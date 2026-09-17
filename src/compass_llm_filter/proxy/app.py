"""Drop-in reverse-proxy: маскирует запросы к LLM, восстанавливает ответы.

Клиент меняет только base URL. Все строковые значения JSON-тела маскируются
рекурсивно (без path-based парсинга форматов OpenAI/Anthropic — нечего
«забыть»); ответ восстанавливается по карте подстановок этого же запроса.
Карта живёт в локальной переменной обработчика: оригиналы не покидают процесс
и умирают вместе с запросом.

Заголовок X-Compass-Entities (JSON-массив строк) — контекстная регистрация:
имена/организации из вашего приложения, которые регулярками не найти.
Заголовок снимается перед пересылкой наверх.
"""
from __future__ import annotations

import base64
import hmac
import json
import pathlib
import uuid

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from compass_llm_filter import Anonymizer
from compass_llm_filter.proxy.config import Settings
from compass_llm_filter.proxy.metrics import Metrics
from compass_llm_filter.proxy.rules import State

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "content-encoding",
}

MASKABLE_METHODS = {"POST", "PUT", "PATCH"}


def _mask_strings(obj, anon: Anonymizer):
    """Заменить PII во всех строках JSON-структуры (в значениях, не в ключах)."""
    if isinstance(obj, str):
        return anon.sanitize_string(obj)
    if isinstance(obj, list):
        return [_mask_strings(item, anon) for item in obj]
    if isinstance(obj, dict):
        return {k: _mask_strings(v, anon) for k, v in obj.items()}
    return obj


def _restore_strings(obj, anon: Anonymizer):
    if isinstance(obj, str):
        return anon.de_anonymize(obj)
    if isinstance(obj, list):
        return [_restore_strings(item, anon) for item in obj]
    if isinstance(obj, dict):
        return {k: _restore_strings(v, anon) for k, v in obj.items()}
    return obj


def _apply_custom_rules(obj, anon: Anonymizer, state):
    """Свои правила поверх встроенных фаз — рекурсивно по тем же строкам."""
    if isinstance(obj, str):
        for rule in state.rules.values():
            if rule.enabled:
                obj = rule.apply(obj, anon)
        return obj
    if isinstance(obj, list):
        return [_apply_custom_rules(item, anon, state) for item in obj]
    if isinstance(obj, dict):
        return {k: _apply_custom_rules(v, anon, state) for k, v in obj.items()}
    return obj


def create_app(settings: Settings, upstream_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    app = FastAPI(title="compass-llm-filter proxy", docs_url=None, redoc_url=None, openapi_url=None)
    state = State(settings)
    app.state.compass = state
    app.state.compass_metrics = metrics = Metrics()
    app.state.compass_client = httpx.AsyncClient(
        base_url=settings.upstream_base_url,
        timeout=httpx.Timeout(120.0, connect=10.0),
        transport=upstream_transport,
    )

    # ── basic-auth консоли и управляющего API (проксируемый трафик не трогаем:
    #    приложение ходит в компас без учётки) ────────────────────────────────
    if settings.auth_user and settings.auth_password:
        @app.middleware("http")
        async def _console_auth(request: Request, call_next):
            path = request.url.path
            if (path in ("/console", "/logo.svg", "/metrics", "/healthz")
                    or path.startswith("/v1/")):
                header = request.headers.get("authorization", "")
                ok = False
                if header.startswith("Basic "):
                    try:
                        creds = base64.b64decode(header[6:]).decode("utf-8")
                        user, _, password = creds.partition(":")
                        ok = (hmac.compare_digest(user.encode(), settings.auth_user.encode())
                              and hmac.compare_digest(password.encode(), settings.auth_password.encode()))
                    except (ValueError, UnicodeDecodeError):
                        ok = False
                if not ok:
                    return Response(
                        status_code=401,
                        headers={"WWW-Authenticate": 'Basic realm="compass"'},
                    )
            return await call_next(request)

    # ── служебные эндпоинты ────────────────────────────────────────────────

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", **state.public_settings(),
                "upstream": settings.upstream_base_url}

    _console_html = (pathlib.Path(__file__).parent / "console.html").read_text(encoding="utf-8")
    _logo_svg = (pathlib.Path(__file__).parent / "logo.svg").read_bytes()

    @app.get("/console", response_class=HTMLResponse)
    async def console():
        # консоль без сборки: один файл, едет внутри pip-пакета
        return HTMLResponse(_console_html)

    @app.get("/logo.svg")
    async def logo():
        return Response(content=_logo_svg, media_type="image/svg+xml")

    @app.get("/metrics")
    async def prometheus_metrics():
        if not settings.metrics_enabled:
            return Response(status_code=404)
        return Response(content=metrics.render(), media_type="text/plain")

    @app.get("/v1/settings")
    async def get_settings():
        return state.public_settings()

    @app.put("/v1/settings")
    async def put_settings(body: dict):
        for key in ("mode", "fail_mode", "anonymization_mode"):
            if key in body:
                value = str(body[key]).strip().lower()
                if value not in (("enforce", "detect") if key == "mode"
                                 else ("closed", "open") if key == "fail_mode"
                                 else ("fake", "placeholders")):
                    return JSONResponse(status_code=400, content={"detail": f"bad {key}: {value}"})
                setattr(state, key, value)
        return state.public_settings()

    @app.get("/v1/rules")
    async def list_rules():
        return {"rules": [r.public() for r in state.rules.values()]}

    @app.post("/v1/rules")
    async def add_rule(body: dict):
        try:
            rule = state.add_rule(body)
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"detail": str(exc)})
        return rule.public()

    @app.patch("/v1/rules/{rule_id}")
    async def toggle_rule(rule_id: str, body: dict):
        rule = state.rules.get(rule_id)
        if not rule:
            return JSONResponse(status_code=404, content={"detail": "rule not found"})
        if "enabled" in body:
            rule.enabled = bool(body["enabled"])
        return rule.public()

    @app.delete("/v1/rules/{rule_id}")
    async def delete_rule(rule_id: str):
        if rule_id not in state.rules:
            return JSONResponse(status_code=404, content={"detail": "rule not found"})
        del state.rules[rule_id]
        return {"deleted": rule_id}

    @app.get("/v1/audit/records")
    async def audit_records():
        return {"records": list(state.audit)}

    # песочница консоли: посмотреть, что уйдёт провайдеру и что вернётся
    @app.post("/v1/sandbox")
    async def sandbox(body: dict):
        anon = Anonymizer(mode=state.anonymization_mode)
        for entity in body.get("entities") or []:
            anon.register_entity(str(entity))
        masked = _mask_strings(body.get("text") or "", anon)
        return {
            "masked": masked,
            "restored": anon.de_anonymize(masked),
            "stats": anon.stats,
            "leaks": anon.leaks_in_text(masked),
        }

    # ── проксирование ──────────────────────────────────────────────────────

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def proxy(request: Request, path: str):
        request_id = uuid.uuid4().hex
        raw_body = await request.body()

        if len(raw_body) > settings.max_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "body too large"})

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP and k.lower() != settings.entities_header}

        # контекстная регистрация сущностей из приложения (fail-closed:
        # кривой заголовок → 400, недомаскированное наружу не уйдёт).
        # Заголовки приходят latin-1 (ASGI), клиенты шлют UTF-8: восстанавливаем;
        # надёжнее всего ASCII-JSON (json.dumps с ensure_ascii по умолчанию).
        entities = []
        if entities_header_value := request.headers.get(settings.entities_header):
            try:
                try:
                    entities_header_value = entities_header_value.encode("latin-1").decode("utf-8")
                except UnicodeDecodeError:
                    pass  # уже честный latin-1 или ASCII — берём как есть
                parsed = json.loads(entities_header_value)
                if not isinstance(parsed, list) or not all(isinstance(e, str) for e in parsed):
                    raise ValueError
                entities = parsed
            except ValueError:
                return JSONResponse(status_code=400, content={
                    "detail": f"{settings.entities_header} must be a JSON array of strings"})

        body_to_send = raw_body
        anon: Anonymizer | None = None
        detect_only = state.mode == "detect"

        if request.method in MASKABLE_METHODS and raw_body:
            try:
                payload = json.loads(raw_body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = None
            if payload is not None:
                try:
                    anon = Anonymizer(mode=state.anonymization_mode)
                    for entity in entities:
                        anon.register_entity(entity)
                    masked_payload = _apply_custom_rules(
                        _mask_strings(payload, anon), anon, state)
                    for text in _iter_strings(masked_payload):
                        if anon.leaks_in_text(text):
                            metrics.inc("compass_blocked_total")
                            state.audit_push(request_id=request_id, path=path, blocked=True,
                                             reason="leak-check failed")
                            if state.fail_mode == "closed":
                                return JSONResponse(status_code=503, content={
                                    "detail": "compass: anonymization failed, request blocked"})
                            # fail-open: пропускаем оригинал, но честно считаем
                            metrics.inc("compass_failopen_total")
                            anon = None
                            break
                    if anon is not None and not detect_only:
                        body_to_send = json.dumps(masked_payload, ensure_ascii=False).encode()
                except Exception:
                    metrics.inc("compass_mask_errors_total")
                    if state.fail_mode == "closed":
                        state.audit_push(request_id=request_id, path=path, blocked=True,
                                         reason="masking error")
                        return JSONResponse(status_code=503, content={
                            "detail": "compass: masking error, request blocked"})
                    metrics.inc("compass_failopen_total")
                    anon = None

        if anon is not None:
            for key, value in anon.stats.items():
                if value:
                    metrics.inc("compass_masked_total", value, type=key)
            state.audit_push(
                request_id=request_id, path=path, mode=state.mode,
                detected={k: v for k, v in anon.stats.items() if v},
                entities=len(entities), blocked=False,
            )

        # detect-режим: считаем и логируем, но провайдеру уходит оригинал
        try:
            upstream_response = await app.state.compass_client.request(
                request.method, f"/{path}",
                headers=headers, content=body_to_send,
                params=request.query_params,
            )
        except httpx.HTTPError as exc:
            metrics.inc("compass_upstream_errors_total")
            return JSONResponse(status_code=502, content={"detail": f"compass: upstream error: {exc}"})

        response_headers = {
            k: v for k, v in upstream_response.headers.items()
            if k.lower() not in HOP_BY_HOP
        }
        content = upstream_response.content
        content_type = upstream_response.headers.get("content-type", "")

        # восстановление оригиналов в ответе (в detect-режим уходил оригинал —
        # восстанавливать нечего)
        if anon is not None and not detect_only and content:
            if "json" in content_type:
                try:
                    restored = _restore_strings(json.loads(content), anon)
                    content = json.dumps(restored, ensure_ascii=False).encode()
                except (json.JSONDecodeError, UnicodeDecodeError):
                    content = anon.de_anonymize(content.decode(errors="replace")).encode()
            elif "event-stream" in content_type:
                # SSE без токен-за-токеном восстановления (roadmap): фейки
                # заменяются по всему буферу целиком
                content = anon.de_anonymize(content.decode(errors="replace")).encode()
            else:
                content = anon.de_anonymize(content.decode(errors="replace")).encode()

        return Response(content=content, status_code=upstream_response.status_code,
                        headers=response_headers)

    return app


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_strings(item)
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_strings(value)


def main() -> None:
    """Точка входа `compass-llm-filter`: настройки из COMPASS_* окружения."""
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
