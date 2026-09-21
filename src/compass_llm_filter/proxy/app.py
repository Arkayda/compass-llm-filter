"""Drop-in reverse-proxy: маскирует запросы к LLM, восстанавливает ответы.

Клиент меняет только base URL. Все строки JSON-тела маскируются рекурсивно,
ответ восстанавливается по карте подстановок этого же запроса; SSE —
токен-за-токеном (SSERestorer). Карта живёт в локальной переменной обработчика,
оригиналы не покидают процесс.

Заголовок X-Compass-Entities (JSON-массив строк) — имена/организации из
приложения, которые регулярками не найти; снимается перед пересылкой наверх.
"""
from __future__ import annotations

import base64
import codecs
import copy
import hmac
import json
import pathlib
import re
import urllib.parse
import uuid

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

from compass_llm_filter import Anonymizer
from compass_llm_filter.core.injection import detect_prompt_injection
from compass_llm_filter.core.validators import set_default_pepper
from compass_llm_filter.proxy.config import Settings
from compass_llm_filter.proxy.metrics import Metrics
from compass_llm_filter.proxy.ratelimit import RateLimiter
from compass_llm_filter.proxy.rules import State

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "content-encoding",
}

MASKABLE_METHODS = {"POST", "PUT", "PATCH"}

# каталог встроенных детекторов: (ключ статистики, название, пример, пояснение)
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

# словарный символ — тот же класс, по которому de_anonymize строит границы слов
def _sanitize_error_msg(msg: str) -> str:
    """Очищает учетные данные и токены из сообщений об ошибках."""
    s = re.sub(r"://([^:@/]+):([^@/]+)@", r"://\1:***@", msg)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{15,}", "Bearer ***", s)
    s = re.sub(r"(?i)(?:api_key|apikey|token|password|secret)=([^&\s]+)", r"\g<0>=***", s)
    return s


def _categorize_entity(orig: str, fake: str) -> str:
    """Определяет категорию сущности для цветовой подсветки в UI."""
    s = orig.strip()
    if s.startswith("@"):
        return "mention"
    if "@" in s and "." in s and not s.startswith("http"):
        return "email"
    if s.startswith(("http://", "https://", "t.me/")):
        return "link"
    if (s.startswith(("sk-", "ghp_", "AKIA", "AIza", "0123456789abcdef")) or
            "BEGIN " in s and "PRIVATE KEY" in s or
            "Bearer " in s or
            "://" in s and "@" in s):
        return "secret"
    if re.search(r"\b\d{4}(?:[ \-]| ?№ ?)\d{6}\b", s):
        return "passport"
    if re.search(r"\b\d{3}-\d{3}-\d{3}\s*\d{2}\b", s):
        return "snils"
    # IP (v4/v6) обязан идти раньше inn: четыре октета дают 10-12 цифр и без
    # этого адрес классифицировался как ИНН
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", s) or ":" in s and re.match(r"^[0-9a-fA-F:]+$", s):
        return "ip"
    digits = re.sub(r"\D", "", s)
    if len(digits) in (10, 12) and ("ИНН" in s or not s.startswith(("+", "8"))):
        return "inn"
    if len(digits) in (13, 15):
        return "ogrn"
    if re.match(r"^[A-Z]{2}\d{2}[A-Z0-9\s]{12,30}$", s):
        return "iban"
    if re.search(r"(?:\+7|8|7)[\s\-(]*\d{3}[\s\-)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}", s):
        return "phone"
    if len(digits) in (16, 18, 19) and re.match(r"^[\d\s\-]+$", s):
        return "card"
    if "." in s and not re.search(r"\s", s):
        return "domain"
    return "names"


class _StreamSlot:
    """Буфер одного строкового поля SSE-потока (ключ — путь в JSON).
    last_obj/path — последнее событие поля, по нему строится синтетическое
    событие для хвоста, не закрывшегося до [DONE].
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


# Листья JSON-путей, по которым модель стримит произвольный текст: anthropic
# content_block_delta (text/partial_json/thinking) и openai choices[].delta
# (content, reasoning_content, tool_calls[].function.arguments). Только в этих
# полях могут оказаться фейки — только они копятся между событиями с hold-логикой.
# Остальные поля под "delta" — атомарные перечисления и служебные блобы
# (delta.type, delta.stop_reason, delta.role, delta.signature): их суффикс
# случайно совпадает с префиксом фейка ("tool_use" -> "e" от example.com,
# base64-подпись -> цифра от фейк-IP), hold обрезал бы значение навсегда, а
# синтетический flush плодил событие с мусорным stop_reason/signature —
# claude-code на таком потоке ломал разбор tool-call.
STREAM_LEAVES = frozenset({
    "text", "partial_json", "thinking",              # anthropic
    "content", "reasoning_content", "arguments",     # openai
    "delta",                                          # legacy: {"delta": "токен"}
})


class SSERestorer:
    """Восстановление оригиналов в SSE-потоке токен-за-токеном.

    Каждое строковое поле копит текст между событиями, поэтому фейк,
    разрезанный провайдером на несколько дельт, склеивается до замены. Хвост —
    строгий префикс какого-то фейка — придерживается до следующей порции,
    наружу «полуфейки» не уходят. Перед [DONE] придержнутое сбрасывается
    синтетическим событием.
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
        """Хвост потока: последняя строка без \\n + синтетические события."""
        self._buf += self._dec.decode(b"", final=True)
        if not self._buf:
            return b""
        line, self._buf = self._buf, ""
        result = self._feed_line(line) + "\n" + "".join(self._flush_events())
        return result.encode("utf-8")

    def _feed_line(self, line: str) -> str:
        if not line.startswith("data:") or not line[5:].strip():
            return line  # комментарии, event:/id:, пустые data:
        payload = line[5:].strip()
        if payload == "[DONE]":
            # перед DONE — сброс придержнутых хвостов
            return "".join(self._flush_events()) + line
        try:
            obj = json.loads(payload)
        except ValueError:
            return "data: " + self._feed_field("_raw", payload)
        # конец блока/сообщения: продолжения дельты не будет — прижатые
        # хвосты выпускаем синтетическими событиями до строки-терминатора
        boundary = isinstance(obj, dict) and obj.get("type") in (
            "content_block_stop", "message_stop")
        prefix = "".join(self._flush_events()) if boundary else ""
        touched = set()
        obj = self._walk(obj, (), touched)
        for key in touched:
            self.fields[key].last_obj = obj
        return prefix + "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

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
        (или до границы блока): клон последнего события поля с хвостом в
        целевом поле. Прочие поля клона сохраняются: enum-дискриминаторы
        (type, role) обязаны доезжать непустыми — обнуление ломало парсер
        tool-call событий на стороне клиента, повтор enum-значения безвреден."""
        events = []
        for key, slot in list(self.fields.items()):
            if not slot.pending:
                continue
            if key.rsplit(".", 1)[-1] not in STREAM_LEAVES:
                slot.pending = ""  # не текстовый поток — хвосту тут не место
                continue
            flushed = self.anon.de_anonymize(slot.pending)
            slot.pending = ""
            if slot.last_obj is None:  # поле вне JSON не встречалось
                events.append("data: " + flushed + "\n\n")
                continue
            clone = copy.deepcopy(slot.last_obj)
            try:
                _set_path(clone, slot.path, flushed)
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            # антропные события парсятся по event-строке — добавляем её,
            # имя события по протоколу совпадает с полем type в data
            head = ""
            if isinstance(clone.get("type"), str):
                head = "event: " + clone["type"] + "\n"
            events.append(
                head + "data: " + json.dumps(clone, ensure_ascii=False, separators=(",", ":")) + "\n\n")
        return events

    def _feed_field(self, key: str, delta: str) -> str:
        slot = self.fields.setdefault(key, _StreamSlot())
        buf = slot.pending + delta
        out = self.anon.de_anonymize(buf)
        # между событиями копятся только текстовые потоки (токены ответа,
        # аргументы tool-call); атомарные поля — перечисления, id, подписи —
        # приходят целиком одним событием, продолжения не будет: придержанный
        # суффикс здесь навсегда потерялся бы (обрезанное stop_reason
        # ломало парсер tool-call), поэтому отдаём сразу
        if key.rsplit(".", 1)[-1] not in STREAM_LEAVES:
            slot.pending = ""
            return out
        # придержать суффикс, который может дорасти до фейка; всё,
        # что фейком стать не может, уходит сразу
        hold = ""
        if self.fakes and out:
            for length in range(min(len(out), self.maxfake - 1), 0, -1):
                suffix = out[-length:]
                if any(f != suffix and f.startswith(suffix) for f in self.fakes):
                    hold = suffix
                    break
        slot.pending = hold
        return out[:len(out) - len(hold)] if hold else out


MAX_RECURSION_DEPTH = 30


def _mask_strings(obj, anon: Anonymizer, depth: int = 0):
    """PII во всех строках JSON (в значениях и строковых ключах, с защитой от глубины рекурсии)."""
    if depth > MAX_RECURSION_DEPTH:
        return obj
    if isinstance(obj, str):
        return anon.sanitize_string(obj)
    if isinstance(obj, list):
        return [_mask_strings(item, anon, depth + 1) for item in obj]
    if isinstance(obj, dict):
        return {
            anon.sanitize_string(k) if isinstance(k, str) else k: _mask_strings(v, anon, depth + 1)
            for k, v in obj.items()
        }
    return obj


def _restore_strings(obj, anon: Anonymizer, depth: int = 0):
    if depth > MAX_RECURSION_DEPTH:
        return obj
    if isinstance(obj, str):
        return anon.de_anonymize(obj)
    if isinstance(obj, list):
        return [_restore_strings(item, anon, depth + 1) for item in obj]
    if isinstance(obj, dict):
        return {
            anon.de_anonymize(k) if isinstance(k, str) else k: _restore_strings(v, anon, depth + 1)
            for k, v in obj.items()
        }
    return obj


def _apply_custom_rules(obj, anon: Anonymizer, state, depth: int = 0):
    """Свои правила поверх встроенных фаз, по тем же строкам и ключам."""
    if depth > MAX_RECURSION_DEPTH:
        return obj
    if isinstance(obj, str):
        for rule in state.rules.values():
            if rule.enabled:
                obj = rule.apply(obj, anon)
        return obj
    if isinstance(obj, list):
        return [_apply_custom_rules(item, anon, state, depth + 1) for item in obj]
    if isinstance(obj, dict):
        res = {}
        for k, v in obj.items():
            new_k = k
            if isinstance(k, str):
                for rule in state.rules.values():
                    if rule.enabled:
                        new_k = rule.apply(new_k, anon)
            res[new_k] = _apply_custom_rules(v, anon, state, depth + 1)
        return res
    return obj


def create_app(settings: Settings, upstream_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    if settings.strict_auth and not (settings.auth_user and settings.auth_password):
        raise ValueError("COMPASS_STRICT_AUTH requires COMPASS_AUTH_USER and COMPASS_AUTH_PASSWORD to be configured")

    if not settings.upstream_base_url.startswith(("http://", "https://")):
        raise ValueError(f"Invalid upstream_base_url scheme: {settings.upstream_base_url}")

    if settings.secret_pepper:
        set_default_pepper(settings.secret_pepper)

    app = FastAPI(title="compass-llm-filter proxy", docs_url=None, redoc_url=None, openapi_url=None)
    state = State(settings)
    app.state.compass = state
    app.state.compass_metrics = metrics = Metrics()
    app.state.sandbox_limiter = RateLimiter(max_requests=60, window_seconds=60.0)
    app.state.compass_client = httpx.AsyncClient(
        base_url=settings.upstream_base_url,
        timeout=httpx.Timeout(120.0, connect=10.0),
        transport=upstream_transport,
        follow_redirects=False,
    )

    # HTTP Security Headers на все ответы
    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response

    # CSRF-защита для управляющих мутирующих эндпоинтов (/v1/settings, /v1/rules)
    @app.middleware("http")
    async def _csrf_protection(request: Request, call_next):
        path = request.url.path
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and (
            path.startswith("/v1/settings") or path.startswith("/v1/rules")
        ):
            sec_fetch = request.headers.get("sec-fetch-site", "").lower()
            if sec_fetch == "cross-site":
                return JSONResponse(status_code=403, content={"detail": "CSRF: Cross-site request rejected"})

            origin = request.headers.get("origin")
            host = request.headers.get("host", "").split(":")[0]
            if origin:
                origin_host = urllib.parse.urlsplit(origin).netloc.split(":")[0]
                if host and origin_host and origin_host != host:
                    return JSONResponse(status_code=403, content={"detail": "CSRF: Origin mismatch rejected"})
            elif "referer" in request.headers:
                referer = request.headers.get("referer", "")
                referer_host = urllib.parse.urlsplit(referer).netloc.split(":")[0]
                if host and referer_host and referer_host != host:
                    return JSONResponse(status_code=403, content={"detail": "CSRF: Referer mismatch rejected"})
        return await call_next(request)

    # basic-auth консоли и управляющего API; проксируемый LLM-трафик не трогаем.
    # /healthz с loopback открыт без пароля — по нему ходит Docker healthcheck
    if settings.auth_user and settings.auth_password:
        @app.middleware("http")
        async def _console_auth(request: Request, call_next):
            path = request.url.path
            if (path in ("/console", "/logo.svg", "/metrics", "/healthz")
                    or path.startswith("/v1/")):
                if path == "/healthz" and request.client and request.client.host in ("127.0.0.1", "::1"):
                    return await call_next(request)
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

    # --- служебные эндпоинты ---

    @app.get("/healthz")
    async def healthz():
        auth_configured = bool(settings.auth_user and settings.auth_password)
        resp = {
            "status": "ok",
            **state.public_settings(),
            "upstream": settings.upstream_base_url,
            "auth_configured": auth_configured,
            "strict_auth": settings.strict_auth,
            "has_pepper": bool(settings.secret_pepper),
            "rate_limit_active": True,
            "csrf_protection": True,
            "csp_active": True,
        }
        if not auth_configured:
            resp["security_warning"] = "Administrative API is unprotected. Configure COMPASS_AUTH_USER and COMPASS_AUTH_PASSWORD."
        return resp

    _console_html = (pathlib.Path(__file__).parent / "console.html").read_text(encoding="utf-8")
    _logo_svg = (pathlib.Path(__file__).parent / "logo.svg").read_bytes()

    @app.get("/console", response_class=HTMLResponse)
    async def console():
        # один html-файл, едет внутри пакета
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

    # каталог детекторов для консоли
    @app.get("/v1/detectors")
    async def detectors():
        return {"detectors": DETECTORS}

    # песочница: что уйдёт провайдеру и что вернётся
    @app.post("/v1/sandbox")
    async def sandbox(request: Request, body: dict):
        client_ip = request.client.host if request.client else "unknown"
        if not app.state.sandbox_limiter.is_allowed(client_ip):
            return JSONResponse(status_code=429, content={"detail": "Too many requests to sandbox"})
        anon = Anonymizer(mode=state.anonymization_mode)
        for entity in body.get("entities") or []:
            anon.register_entity(str(entity))
        text = body.get("text") or ""
        # тот же конвейер, что у прокси-пути: сперва встроенные детекторы, затем
        # кастомные правила — иначе песочница (и построенное на ней превью в
        # хелпеске) соврала бы, покажет меньше, чем уйдёт провайдеру
        masked = _apply_custom_rules(_mask_strings(text, anon), anon, state)
        injections = detect_prompt_injection(text)
        replacements = [
            {
                "fake": fake,
                "original": orig,
                "category": _categorize_entity(orig, fake),
            }
            for fake, orig in anon.reverse_map().items()
        ]
        return {
            "masked": masked,
            "restored": anon.de_anonymize(masked),
            "stats": anon.stats,
            "leaks": anon.leaks_in_text(masked),
            "injections": injections,
            "replacements": replacements,
        }

    # --- проксирование ---

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def proxy(request: Request, path: str):
        request_id = uuid.uuid4().hex
        raw_body = await request.body()

        if len(raw_body) > settings.max_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "body too large"})

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP and k.lower() != settings.entities_header}

        # сущности из приложения; кривой заголовок -> 400 (fail-closed).
        # ASGI отдаёт заголовки в latin-1, а клиенты шлют UTF-8 — восстанавливаем
        entities = []
        if entities_header_value := request.headers.get(settings.entities_header):
            try:
                try:
                    entities_header_value = entities_header_value.encode("latin-1").decode("utf-8")
                except UnicodeDecodeError:
                    pass  # latin-1 или ASCII, берём как есть
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
        injections: list[str] = []

        if request.method in MASKABLE_METHODS and raw_body:
            try:
                payload = json.loads(raw_body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = None
            if payload is not None:
                for text in _iter_strings(payload):
                    if inj := detect_prompt_injection(text):
                        injections.extend(inj)
                if injections:
                    metrics.inc("compass_prompt_injections_total", len(injections))
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
                                             reason="leak-check failed",
                                             injections=list(set(injections)))
                            if state.fail_mode == "closed":
                                return JSONResponse(status_code=503, content={
                                    "detail": "compass: anonymization failed, request blocked"})
                            # fail-open: пропускаем оригинал
                            metrics.inc("compass_failopen_total")
                            anon = None
                            break
                    if anon is not None and not detect_only:
                        body_to_send = json.dumps(masked_payload, ensure_ascii=False).encode()
                except Exception:
                    metrics.inc("compass_mask_errors_total")
                    if state.fail_mode == "closed":
                        state.audit_push(request_id=request_id, path=path, blocked=True,
                                         reason="masking error",
                                         injections=list(set(injections)))
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
                injections=list(set(injections)),
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
            clean_err = _sanitize_error_msg(str(exc))
            return JSONResponse(status_code=502, content={"detail": f"compass: upstream error: {clean_err}"})

        response_headers = {
            k: v for k, v in upstream_response.headers.items()
            if k.lower() not in HOP_BY_HOP
        }
        content_type = upstream_response.headers.get("content-type", "")

        # SSE: восстановление токен-за-токеном, кадры уходят по мере прихода
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

        # восстановление в обычном (буферизованном) ответе
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


def _iter_strings(obj, depth: int = 0):
    if depth > MAX_RECURSION_DEPTH:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_strings(item, depth + 1)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                yield key
            yield from _iter_strings(value, depth + 1)


def main() -> None:
    """Точка входа `compass-llm-filter`."""
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
