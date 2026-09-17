"""Drop-in reverse-proxy: маскирует запросы к LLM, восстанавливает ответы.

Клиент меняет только base URL. Все строковые значения JSON-тела маскируются
рекурсивно (без path-based парсинга форматов OpenAI/Anthropic — нечего
«забыть»); ответ восстанавливается по карте подстановок этого же запроса.
SSE-стриминг — токен-за-токеном: фейк, разрезанный границей дельт, склеивается
до замены (SSERestorer). Карта живёт в локальной переменной обработчика:
оригиналы не покидают процесс и умирают вместе с запросом.

Заголовок X-Compass-Entities (JSON-массив строк) — контекстная регистрация:
имена/организации из вашего приложения, которые регулярками не найти.
Заголовок снимается перед пересылкой наверх.
"""
from __future__ import annotations

import base64
import codecs
import copy
import hmac
import json
import pathlib
import re
import uuid

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

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

# каталог встроенных детекторов: (стат-ключ, название, пример, комментарий)
DETECTORS = [
    ("names", "Имена, фамилии, ники, организации", "Иванов Пётр, @ivanov_petrov, ООО Ромашка",
     "по карте из приложения: X-Compass-Entities / register_entity()"),
    ("cards", "Банковские карты", "4111 1111 1111 1111", "валидация по Луну, фейк с валидной суммой"),
    ("accounts", "СНИЛС", "112-233-445 95", "контрольная сумма, разделители сохраняются"),
    ("inns", "ИНН юрлица и ИП", "7707083893, 500100732259", "10/12 цифр, обе контрольные"),
    ("ogrns", "ОГРН / ОГРНИП", "1027700132195", "13/15 цифр"),
    ("passports", "Паспорт РФ", "4509 123456", "серия и номер явной формой"),
    ("ibans", "IBAN", "GB82 WEST 1234 5698 7654 32", "ISO 13616 (mod 97), страна и длина сохраняются"),
    ("phones", "Телефоны", "+7 912 345-67-89", "формат и раскладка сохраняются"),
    ("emails", "E-mail", "ivan@romashka.ru", "фейк на example.com/org/net"),
    ("links", "Ссылки", "https://t.me/x/123", "фейк example.com/<hash>"),
    ("mentions", "@упоминания", "@ivanov_petrov", "ник того же стиля"),
    ("domains", "Домены и wildcard", "chat.corp.ru, *.corp.ru", "сервисный префикс сохраняется"),
    ("ips", "IPv4", "192.168.0.66", "приватные остаются приватными, публичные — RFC 5737"),
    ("secrets", "Секреты и токены", "sk-…, ghp_…, AKIA…, JWT, Bearer …, api_key=…",
     "приватные ключи, OpenAI/GitHub/AWS/Google/Slack/Telegram/Stripe/GLM, "
     "пары «метка: значение», connection strings"),
    ("custom", "Свои правила", "ORD-123456", "regex через /v1/rules или файл при старте"),
]
DETECTORS = [
    {"id": key, "title": title, "example": example, "note": note}
    for key, title, example, note in DETECTORS
]

# «словарный» символ — тот же класс, по которому de_anonymize строит границы
# слов; всё после последнего НЕ-словарного символа считается недописанным
# токеном и в стриме не обрабатывается до появления границы
_WORDCH = re.compile(r"[\wА-Яа-яЁё@.\-]")


class _StreamSlot:
    """Накопитель одного строкового поля SSE-потока (ключ — путь в JSON).

    last_obj/path — форма последнего события, в котором поле встречалось:
    по ней строится синтетическое финальное событие для хвоста, не
    закрывшегося до [DONE] (фейк в самом конце генерации).
    """
    __slots__ = ("pending", "last_obj", "path")

    def __init__(self) -> None:
        self.pending = ""
        self.last_obj = None
        self.path = ()


def _set_path(obj, path: tuple, value) -> None:
    cur = obj
    for p in path[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    last = path[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


class SSERestorer:
    """Восстановление оригиналов в SSE-потоке токен-за-токеном.

    Каждое строковое поле (например choices.0.delta.content) копит текст между
    событиями, поэтому фейк, разрезанный провайдером на несколько дельт,
    склеивается до замены. Хвост, являющийся строгим префиксом какого-то
    фейка, придерживается до следующей порции — наружу недопустимые
    «полуфейки» не уходят. Перед [DONE] придержнутый хвост сбрасывается
    синтетическим событием той же формы, что последнее событие поля.
    """

    def __init__(self, anon: Anonymizer) -> None:
        self.anon = anon
        self.fakes = list(anon.reverse_map())
        self.maxfake = max((len(f) for f in self.fakes), default=0)
        self.fields: dict[str, _StreamSlot] = {}
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._buf = ""

    def feed_bytes(self, b: bytes) -> bytes:
        text = self._dec.decode(b)
        if not text and not self._buf:
            return b""
        self._buf += text
        out = []
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            cr = line.endswith("\r")
            if cr:
                line = line[:-1]
            out.append(self._feed_line(line) + ("\r\n" if cr else "\n"))
        return "".join(out).encode("utf-8") if out else b""

    def tail(self) -> bytes:
        """Финальный недообработанный хвост (строка без \\n в конце потока)."""
        self._buf += self._dec.decode(b"", final=True)
        if not self._buf:
            return b""
        line, self._buf = self._buf, ""
        result = self._feed_line(line) + "\n" + "".join(self._flush_events())
        return result.encode("utf-8")

    def _feed_line(self, line: str) -> str:
        if not line.startswith("data:") or not line[5:].strip():
            return line  # комментарии (:...), event:/id:/retry:, пустые data:
        payload = line[5:].strip()
        if payload == "[DONE]":
            # сначала сброс придержнутых хвостов синтетическими событиями
            return "".join(self._flush_events()) + line
        try:
            obj = json.loads(payload)
        except ValueError:
            return "data: " + self._feed_field("_raw", payload)
        touched = set()
        obj = self._walk(obj, (), touched)
        for key in touched:
            self.fields[key].last_obj = obj
        return "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def _walk(self, obj, path, touched):
        if isinstance(obj, str):
            key = ".".join(path)
            slot = self.fields.setdefault(key, _StreamSlot())
            slot.path = path
            touched.add(key)
            return self._feed_field(key, obj)
        if isinstance(obj, list):
            return [self._walk(v, path + (str(i),), touched) for i, v in enumerate(obj)]
        if isinstance(obj, dict):
            return {k: self._walk(v, path + (k,), touched) for k, v in obj.items()}
        return obj

    def _flush_events(self) -> list[str]:
        """Синтетические события для хвостов, не закрывшихся до конца потока
        (фейк в самом конце генерации без границы после него). Форма — клон
        последнего события поля, прочие строковые поля обнулены."""
        events = []
        for key, slot in list(self.fields.items()):
            if not slot.pending:
                continue
            flushed = self.anon.de_anonymize(slot.pending)
            slot.pending = ""
            if slot.last_obj is None:  # поле вне JSON не встречалось
                events.append("data: " + flushed + "\n\n")
                continue
            clone = copy.deepcopy(slot.last_obj)
            for other_key, other in self.fields.items():
                if other is not slot and other.last_obj is slot.last_obj:
                    try:
                        _set_path(clone, other.path, "")
                    except (KeyError, IndexError, TypeError, ValueError):
                        pass
            try:
                _set_path(clone, slot.path, flushed)
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            events.append(
                "data: " + json.dumps(clone, ensure_ascii=False, separators=(",", ":")) + "\n\n")
        return events

    def _feed_field(self, key: str, delta: str) -> str:
        slot = self.fields.setdefault(key, _StreamSlot())
        buf = slot.pending + delta
        # обрабатывать можно только до последнего граничного символа: замена по
        # границам слов не должна срабатывать на «конце буфера», за которым
        # может прийти буква (тогда слова нет)
        cut = 0
        for i in range(len(buf) - 1, -1, -1):
            if not _WORDCH.match(buf[i]):
                cut = i + 1
                break
        out = self.anon.de_anonymize(buf[:cut]) if cut else ""
        # придержать строгий префикс фейка, разрезанный границей дельт
        hold = ""
        if self.fakes and out:
            for length in range(min(len(out), self.maxfake - 1), 0, -1):
                suffix = out[-length:]
                if any(f != suffix and f.startswith(suffix) for f in self.fakes):
                    hold = suffix
                    break
        slot.pending = hold + buf[cut:]
        return out[:len(out) - len(hold)] if hold else out


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
        state.save_state()
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
        state.save_state()
        return rule.public()

    @app.patch("/v1/rules/{rule_id}")
    async def toggle_rule(rule_id: str, body: dict):
        rule = state.rules.get(rule_id)
        if not rule:
            return JSONResponse(status_code=404, content={"detail": "rule not found"})
        if "enabled" in body:
            rule.enabled = bool(body["enabled"])
        state.save_state()
        return rule.public()

    @app.delete("/v1/rules/{rule_id}")
    async def delete_rule(rule_id: str):
        if rule_id not in state.rules:
            return JSONResponse(status_code=404, content={"detail": "rule not found"})
        del state.rules[rule_id]
        state.save_state()
        return {"deleted": rule_id}

    @app.get("/v1/audit/records")
    async def audit_records():
        return {"records": list(state.audit)}

    # каталог встроенных детекторов (справочно, для консоли; ~16 категорий)
    @app.get("/v1/detectors")
    async def detectors():
        return {"detectors": DETECTORS}

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
        upstream_request = app.state.compass_client.build_request(
            request.method, f"/{path}",
            headers=headers, content=body_to_send,
            params=request.query_params,
        )
        try:
            upstream_response = await app.state.compass_client.send(
                upstream_request, stream=True)
        except httpx.HTTPError as exc:
            metrics.inc("compass_upstream_errors_total")
            return JSONResponse(status_code=502, content={"detail": f"compass: upstream error: {exc}"})

        response_headers = {
            k: v for k, v in upstream_response.headers.items()
            if k.lower() not in HOP_BY_HOP
        }
        content_type = upstream_response.headers.get("content-type", "")

        # SSE-стриминг: восстановление токен-за-токеном, кадры уходят клиенту
        # по мере прихода от провайдера (в detect-режим уходил оригинал —
        # восстанавливать нечего, поток проходит как есть)
        if anon is not None and not detect_only and "event-stream" in content_type:
            restorer = SSERestorer(anon)

            async def sse_gen():
                try:
                    async for chunk in upstream_response.aiter_bytes():
                        piece = restorer.feed_bytes(chunk)
                        if piece:
                            yield piece
                    piece = restorer.tail()
                    if piece:
                        yield piece
                finally:
                    await upstream_response.aclose()

            return StreamingResponse(
                sse_gen(), status_code=upstream_response.status_code,
                headers=response_headers)

        content = await upstream_response.aread()
        await upstream_response.aclose()

        # восстановление оригиналов в ответе (в detect-режим уходил оригинал —
        # восстанавливать нечего); SSE обрабатывается стримингом выше
        if anon is not None and not detect_only and content:
            if "json" in content_type:
                try:
                    restored = _restore_strings(json.loads(content), anon)
                    content = json.dumps(restored, ensure_ascii=False).encode()
                except (json.JSONDecodeError, UnicodeDecodeError):
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
