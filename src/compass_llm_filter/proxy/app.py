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
import ipaddress
import json
import pathlib
import re
import socket
import urllib.parse
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

from compass_llm_filter import Anonymizer
from compass_llm_filter.core.injection import detect_prompt_injection
from compass_llm_filter.core.validators import set_default_pepper
from compass_llm_filter.proxy.config import Settings
from compass_llm_filter.proxy.metrics import Metrics
from compass_llm_filter.proxy.ratelimit import RateLimiter
from compass_llm_filter.proxy.rules import (MAX_RULE_INPUT_CHARS, DuplicateRuleError,
                                            RuleInputTooLong, State)

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "content-encoding",
}

# заголовки, вырезаемые из ЗАПРОСА наверх: content-encoding — end-to-end,
# не hop-by-hop; сжатое тело клиента мы не перекодируем — заголовок обязан
# ехать вместе с ним, иначе апстрим получает сломанный запрос
REQUEST_HOP_BY_HOP = HOP_BY_HOP - {"content-encoding"}

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
    s = re.sub(r"://([^:@/\s]+):([^@/\s]+)@", r"://\1:***@", msg)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{15,}", "Bearer ***", s)
    # метку сохраняем, значение вырезаем целиком (раньше \g<0> возвращал его обратно)
    s = re.sub(
        r"(?i)\b((?:api[-_]?key|apikey|access[-_]?token|key|token|secret|password|passwd|pwd)"
        r"\s*[=:])[^&\s'\"]+",
        r"\1***", s)
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
        # event:/id: относятся к СЛЕДУЮЩЕЙ data:-строке; придерживаем их,
        # чтобы синтетический flush на границе блока не разрывал пару
        self._pending_fields: list[str] = []

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
        # errors="replace": одиночные суррогаты (\ud800) из upstream-JSON не
        # должны ронять поток посреди ответа — они превращаются в U+FFFD
        return "".join(out).encode("utf-8", errors="replace") if out else b""

    def tail(self) -> bytes:
        """Хвост потока: последняя строка без \\n + синтетические события."""
        self._buf += self._dec.decode(b"", final=True)
        if not self._buf:
            return b""
        line, self._buf = self._buf, ""
        result = self._feed_line(line) + "\n" + "".join(self._flush_events())
        return result.encode("utf-8", errors="replace")

    def _feed_line(self, line: str) -> str:
        if line.startswith(("event:", "id:")):
            # придерживаем: emit вместе со своей data:-строкой (см. ниже);
            # иначе синтетический flush на границе блока вставлялся между
            # event: и data: и реальное событие теряло имя
            self._pending_fields.append(line)
            return ""
        if not line.startswith("data:"):
            return line  # комментарии (:), retry:, пустые строки — как раньше
        buffered = "".join(f + "\n" for f in self._pending_fields)
        self._pending_fields.clear()
        # по спецификации SSE у значения data убирается РОВНО ОДИН ведущий
        # пробел; .strip() искажал payload с значимыми пробелами
        payload = line[5:]
        if payload.startswith(" "):
            payload = payload[1:]
        if not payload.strip():  # пустые data: — пара event:/data: сохраняется
            return buffered + line
        if payload == "[DONE]":
            # перед DONE — сброс придержнутых хвостов (синтетика самодостаточна:
            # свои event:-строки, затем придержанные поля и сама строка DONE)
            return "".join(self._flush_events()) + buffered + line
        try:
            obj = json.loads(payload)
        except ValueError:
            return buffered + "data: " + self._feed_field("_raw", payload)
        # конец блока/сообщения: продолжения дельты не будет — прижатые
        # хвосты выпускаем синтетическими событиями до строки-терминатора;
        # синтетика идёт ПЕРЕД придержанной event:-строкой, чтобы каждая
        # event: осталась соседней со своей data:
        boundary = isinstance(obj, dict) and obj.get("type") in (
            "content_block_stop", "message_stop")
        prefix = "".join(self._flush_events()) if boundary else ""
        touched = set()
        obj = self._walk(obj, (), touched)
        for key in touched:
            self.fields[key].last_obj = obj
        return prefix + buffered + "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

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


def _unique_key(res: dict, key) -> str:
    """Маскированные ключи двух разных оригиналов могут совпасть (например,
    обе карты -> [CARD]); молчаливая перезапись теряла бы значение — суффиксуем."""
    if key not in res:
        return key
    base = key
    n = 2
    while key in res:
        key = f"{base}#{n}"
        n += 1
    return key


def _mask_strings(obj, anon: Anonymizer, depth: int = 0):
    """PII во всех строках JSON (в значениях и строковых ключах, с защитой от глубины рекурсии)."""
    if depth > MAX_RECURSION_DEPTH:
        return obj
    if isinstance(obj, str):
        return anon.sanitize_string(obj)
    if isinstance(obj, list):
        return [_mask_strings(item, anon, depth + 1) for item in obj]
    if isinstance(obj, dict):
        res = {}
        for k, v in obj.items():
            new_k = anon.sanitize_string(k) if isinstance(k, str) else k
            res[_unique_key(res, new_k)] = _mask_strings(v, anon, depth + 1)
        return res
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
        # на мегабайтных строках правило может уйти в полиномиальный возврат:
        # гарантировать маскировку нельзя — уходим в fail-политику запроса
        if len(obj) > MAX_RULE_INPUT_CHARS and any(
                r.enabled for r in state.rules.values()):
            raise RuleInputTooLong(len(obj))
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
            res[_unique_key(res, new_k)] = _apply_custom_rules(v, anon, state, depth + 1)
        return res
    return obj


# числовые формы хоста, которые ip_address не парсит, а getaddrinfo резолвит
# в 127.0.0.1: чистый десятичный (2130706433), hex (0x7f000001, 0x7f.0.0.1),
# усечённая точечная запись (127.1)
_NUMERIC_HOST_RE = re.compile(r"^(?:0x[0-9a-fA-F.]+|\d+(?:\.\d+){0,2})$")


def _ip_is_internal(ip) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_unspecified)


def _validate_upstream_host(url: str, allow_private: bool) -> None:
    """SSRF-защита: апстрим не должен указывать на внутренние адреса,
    если это явно не разрешено (локальный мок/dev). Проверяются IP-литералы,
    localhost, числовые формы вида 127.1/0x7f000001/2130706433 и резолв
    домена через getaddrinfo при старте (DNS-ответ мог бы смениться между
    проверкой и запросом — стартовая проверка отсекает очевидные случаи)."""
    if allow_private:
        return
    host = urllib.parse.urlsplit(url).hostname or ""
    if host.lower() == "localhost":
        raise ValueError(f"upstream host {host!r} is internal; set COMPASS_ALLOW_PRIVATE_UPSTREAM=true only for local dev")
    if _NUMERIC_HOST_RE.match(host):
        raise ValueError(f"upstream host {host!r} is a numeric address form; set COMPASS_ALLOW_PRIVATE_UPSTREAM=true only for local dev")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if _ip_is_internal(ip):
            raise ValueError(f"upstream host {host!r} is an internal IP; set COMPASS_ALLOW_PRIVATE_UPSTREAM=true only for local dev")
        return  # публичный IP-литерал
    # доменное имя: резолвим один раз и проверяем каждый возвращённый адрес;
    # нерезолвящееся имя пропускаем (моки/dev-имена, DNS может подхватиться позже)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return
    for info in infos:
        addr = info[4][0].split("%", 1)[0]  # срезаем scope у IPv6 link-local
        try:
            aip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_internal(aip):
            raise ValueError(f"upstream host {host!r} resolves to internal address {addr}; set COMPASS_ALLOW_PRIVATE_UPSTREAM=true only for local dev")


def create_app(settings: Settings, upstream_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    if settings.strict_auth and not (settings.auth_user and settings.auth_password):
        raise ValueError("COMPASS_STRICT_AUTH requires COMPASS_AUTH_USER and COMPASS_AUTH_PASSWORD to be configured")

    if not settings.upstream_base_url.startswith(("http://", "https://")):
        raise ValueError(f"Invalid upstream_base_url scheme: {settings.upstream_base_url}")
    _validate_upstream_host(settings.upstream_base_url, settings.allow_private_upstream)

    if settings.secret_pepper:
        set_default_pepper(settings.secret_pepper)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        yield
        # пул соединений апстрима закрывается при остановке сервера — раньше
        # клиент не закрывался вовсе и соединения утекали
        await _app.state.compass_client.aclose()

    app = FastAPI(title="compass-llm-filter proxy", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=_lifespan)
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

    # CSRF-защита для управляющих мутирующих эндпоинтов (/v1/settings,
    # /v1/rules, /v1/sandbox)
    @app.middleware("http")
    async def _csrf_protection(request: Request, call_next):
        path = request.url.path
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and (
            path.startswith(("/v1/settings", "/v1/rules", "/v1/sandbox"))
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
    # Защищаются ТОЛЬКО конкретные управляющие пути: /v1/* — это заодно и
    # стандартные пути LLM API (/v1/chat/completions, /v1/models), их закрыть —
    # сломать всех OpenAI-совместимых клиентов.
    # /healthz с loopback открыт без пароля — по нему ходит Docker healthcheck
    if settings.auth_user and settings.auth_password:
        @app.middleware("http")
        async def _console_auth(request: Request, call_next):
            path = request.url.path
            admin = (
                path in ("/console", "/console.js", "/logo.svg", "/metrics", "/healthz",
                         "/v1/settings", "/v1/rules", "/v1/audit/records",
                         "/v1/detectors", "/v1/sandbox")
                or path.startswith("/v1/rules/")
            )
            if admin:
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

    # HTTP Security Headers на ВСЕ ответы (включая 401/403 от мидлварей выше):
    # регистрируется последним => выполняется внешним, заголовки попадают и в ошибки.
    # script-src без 'unsafe-inline': весь JS консоли — внешний файл + делегирование
    # data-action (style-src оставлен 'unsafe-inline' — инъекция CSS не исполняет код)
    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response

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
    _console_js = (pathlib.Path(__file__).parent / "console.js").read_text(encoding="utf-8")
    _logo_svg = (pathlib.Path(__file__).parent / "logo.svg").read_bytes()

    @app.get("/console", response_class=HTMLResponse)
    async def console():
        # один html-файл, едет внутри пакета
        return HTMLResponse(_console_html)

    @app.get("/console.js")
    async def console_js():
        return Response(content=_console_js,
                        media_type="text/javascript; charset=utf-8")

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
        except DuplicateRuleError as exc:
            return JSONResponse(status_code=409, content={"detail": str(exc)})
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
            # строго булево значение: JSON-строка "false" проходила bool()
            # и включала выключенное правило
            if not isinstance(body["enabled"], bool):
                return JSONResponse(status_code=400, content={
                    "detail": "enabled must be a boolean"})
            rule.enabled = body["enabled"]
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
        try:
            masked = _apply_custom_rules(_mask_strings(text, anon), anon, state)
        except RuleInputTooLong:
            return JSONResponse(status_code=400, content={
                "detail": f"text exceeds custom-rule input limit ({MAX_RULE_INPUT_CHARS} chars)"})
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
        # грубый отсев по Content-Length до чтения тела (анти-DoS);
        # тело без честного Content-Length (chunked) читается ограниченно:
        # как только суммарный размер перевалил за лимит — 413 сразу,
        # не дочитывая поток злоумышленника целиком
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit():
            if int(content_length) > settings.max_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "body too large"})
            raw_body = await request.body()
        else:
            chunks: list[bytes] = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.max_body_bytes:
                    return JSONResponse(status_code=413, content={"detail": "body too large"})
                chunks.append(chunk)
            raw_body = b"".join(chunks)

        if len(raw_body) > settings.max_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "body too large"})

        # accept-encoding не пересылаем: httpx ставит свой список по фактически
        # установленным декодерам; ответ мы всегда отдаём распакованным, а
        # br/zstd от клиента приводили к нечитаемым байтам у клиента
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in REQUEST_HOP_BY_HOP
                   and k.lower() != "accept-encoding"
                   and k.lower() != settings.entities_header}

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
        forward_query = None  # None — проксировать query как есть
        passthrough = False   # fail-open где-то: весь запрос уходит оригиналом

        def _new_anon() -> Anonymizer:
            a = Anonymizer(mode=state.anonymization_mode)
            for entity in entities:
                a.register_entity(entity)
            return a

        # ПДн в query-параметрах (?q=Иван Иванов): маскируем значения тем же
        # конвейером, что и тело; имена параметров не трогаем (контракт API)
        if list(request.query_params.keys()):
            try:
                q_anon = anon or _new_anon()
                masked_pairs = [
                    (k, _apply_custom_rules(q_anon.sanitize_string(v), q_anon, state))
                    for k, v in request.query_params.multi_items()
                ]
                if any(q_anon.leaks_in_text(v) for _k, v in masked_pairs):
                    if state.mode == "enforce":
                        metrics.inc("compass_blocked_total")
                        state.audit_push(request_id=request_id, path=path, mode=state.mode,
                                         blocked=True, reason="leak-check failed (query)",
                                         injections=list(set(injections)))
                        if state.fail_mode == "closed":
                            return JSONResponse(status_code=503, content={
                                "detail": "compass: anonymization failed, request blocked"})
                        metrics.inc("compass_failopen_total")
                        passthrough = True
                    else:
                        # detect (shadow) не блокирует: провайдер и так видит
                        # оригинал; инцидент фиксируем ошибкой маскирования
                        metrics.inc("compass_mask_errors_total")
                        state.audit_push(request_id=request_id, path=path, mode=state.mode,
                                         reason="leak-check failed (detect mode: query passthrough)",
                                         blocked=False,
                                         injections=list(set(injections)))
                else:
                    anon = q_anon
                    if not detect_only:
                        forward_query = masked_pairs
            except Exception:
                metrics.inc("compass_mask_errors_total")
                if state.fail_mode == "closed":
                    state.audit_push(request_id=request_id, path=path, mode=state.mode,
                                     blocked=True, reason="masking error (query)",
                                     injections=list(set(injections)))
                    return JSONResponse(status_code=503, content={
                        "detail": "compass: masking error, request blocked"})
                metrics.inc("compass_failopen_total")
                passthrough = True

        if request.method in MASKABLE_METHODS and raw_body:
            if "content-encoding" in request.headers and not passthrough:
                # сжатое тело не раскладывается в JSON — маскировать нельзя:
                # enforce+closed блокирует (наверх не уезжает незамаскированный
                # ПДн), detect/fail-open пропускают сырые байты как есть,
                # content-encoding при них (заголовок больше не вырезается)
                metrics.inc("compass_mask_errors_total")
                if state.mode == "enforce" and state.fail_mode == "closed":
                    state.audit_push(request_id=request_id, path=path, mode=state.mode,
                                     blocked=True,
                                     reason="compressed request body cannot be masked",
                                     injections=list(set(injections)))
                    return JSONResponse(status_code=503, content={
                        "detail": "compass: compressed request body cannot be masked, request blocked"})
                state.audit_push(request_id=request_id, path=path, mode=state.mode,
                                 blocked=False, reason="compressed body passthrough",
                                 injections=list(set(injections)))
            else:
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
                    if not passthrough:
                        try:
                            if anon is None:
                                anon = _new_anon()
                            masked_payload = _apply_custom_rules(
                                _mask_strings(payload, anon), anon, state)
                            for text in _iter_strings(masked_payload):
                                if anon.leaks_in_text(text):
                                    if state.mode == "enforce":
                                        metrics.inc("compass_blocked_total")
                                        state.audit_push(request_id=request_id, path=path,
                                                         mode=state.mode, blocked=True,
                                                         reason="leak-check failed",
                                                         injections=list(set(injections)))
                                        if state.fail_mode == "closed":
                                            return JSONResponse(status_code=503, content={
                                                "detail": "compass: anonymization failed, request blocked"})
                                        # fail-open: пропускаем оригинал целиком
                                        metrics.inc("compass_failopen_total")
                                        anon = None
                                        forward_query = None
                                        break
                                    # detect (shadow) не блокирует: провайдер и так
                                    # видит оригинал; инцидент фиксируем ошибкой
                                    # маскирования, запрос уходит как обычно
                                    metrics.inc("compass_mask_errors_total")
                                    state.audit_push(request_id=request_id, path=path,
                                                     mode=state.mode, blocked=False,
                                                     reason="leak-check failed (detect mode: passthrough)",
                                                     injections=list(set(injections)))
                                    break
                            if anon is not None and not detect_only:
                                body_to_send = json.dumps(masked_payload, ensure_ascii=False).encode()
                        except Exception:
                            metrics.inc("compass_mask_errors_total")
                            if state.fail_mode == "closed":
                                state.audit_push(request_id=request_id, path=path,
                                                 mode=state.mode, blocked=True,
                                                 reason="masking error",
                                                 injections=list(set(injections)))
                                return JSONResponse(status_code=503, content={
                                    "detail": "compass: masking error, request blocked"})
                            metrics.inc("compass_failopen_total")
                            anon = None
                            forward_query = None

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
            params=forward_query if forward_query is not None else request.query_params,
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

        # SSE: восстановление токен-за-токеном, кадры уходят по мере прихода.
        # В detect-режиме (shadow) и после fail-open апстрим видит оригинал —
        # восстанавливать нечего, но стримить всё равно нужно: буферизация до
        # конца ответа ломала бы TTFT и длинные потоки
        if "event-stream" in content_type:
            restore = anon is not None and not detect_only
            restorer = SSERestorer(anon) if restore else None

            async def sse_gen():
                try:
                    if restore:
                        async for chunk in upstream_response.aiter_bytes():
                            piece = restorer.feed_bytes(chunk)
                            if piece:
                                yield piece
                        piece = restorer.tail()
                        if piece:
                            yield piece
                    else:
                        async for chunk in upstream_response.aiter_bytes():
                            yield chunk
                finally:
                    await upstream_response.aclose()

            return StreamingResponse(
                sse_gen(), status_code=upstream_response.status_code,
                headers=response_headers)

        content = await upstream_response.aread()
        await upstream_response.aclose()

        # восстановление в обычном (буферизованном) ответе; анонимайзер без
        # находок (пустая карта подстановок) оставляет байты нетронутыми —
        # бинарные ответы (аудио/файлы) не прогоняются через
        # decode(errors="replace") и не портятся U+FFFD
        if (anon is not None and not detect_only and content
                and anon.reverse_map()):
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
