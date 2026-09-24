"""Секреты: API-ключи, токены, приватные ключи, пары «метка: значение».

Правила про префиксы и формы известных ключей; в парах присваивания
(api_key=..., password:...) заменяется только значение. Замена —
детерминированный мусор той же длины и формы, чтобы модель не теряла
структуру текста.
"""
from __future__ import annotations

import hashlib
import re

from compass_llm_filter.core.validators import det_rng

_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
PLACEHOLDER = "[SECRET]"

# режимы: whole — весь матч; token — группу 1 (метку перед ней сохранить);
# kv — группу 2 между меткой (группа 1) и хвостом (группа 3)
# (имя, regex, режим)
RULES: list[tuple[str, re.Pattern, str]] = [
    # приватные ключи: блок целиком или отдельный заголовок
    ("private_key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----)?"
    ), "whole"),
    # OpenAI и совместимые: в хвосте обязательна цифра — иначе «слова через
    # дефис» (sk-warehouse-certified-professional) считаются ключом
    ("openai_key", re.compile(r"\bsk-(?:proj-)?(?=[A-Za-z_-]*\d)[A-Za-z0-9_-]{16,}\b"), "whole"),
    # GitHub tokens
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), "whole"),
    ("github_app", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "whole"),
    # AWS access keys
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "whole"),
    # Google API
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "whole"),
    # Slack
    ("slack_token", re.compile(r"\bxox[abprse]-[0-9A-Za-z-]{10,}\b"), "whole"),
    # Telegram bot API
    ("tg_bot_key", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"), "whole"),
    # Stripe
    ("stripe_key", re.compile(r"\b[spkr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), "whole"),
    # GLM / BigModel: id HEX32 + '.' + пароль
    ("glm_key", re.compile(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{10,20}\b"), "whole"),
    # JWT (три base64url-сегмента, ey..-заголовок)
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b"), "whole"),
    # Bearer <токен> — регистр слова любой (bearer/Bearer/BEARER)
    ("bearer", re.compile(r"\b(?i:bearer) ([A-Za-z0-9._~+/=-]{20,})"), "token"),
    # пары ключ=значение: метку сохраняем, значение меняем. Метка может нести
    # хвост «_слово» (SECRET_KEY=, api_key_id=) и приставку «слово_»
    # (client_secret=); хвост обязан начинаться с -/_ — иначе «tokenizer:»
    # распознался бы как метка token
    ("kv_secret", re.compile(
        r"(?i)(?:\b|(?<=[_-]))((?:api[-_]?key|apikey|access[-_]?token|secret|password|passwd|pwd|token)(?:[-_]\w+)?"
        r"\s*[:=]\s*[\"']?)([A-Za-z0-9+/_=-]{12,})([\"']?)"), "kv"),
    # connection string: scheme://user:PASSWORD@HOST; хост отдельной группой —
    # доменная фаза домены после @ не трогает (часть e-mail), а хост БД
    # утечь не должен (поддерживаются домена из одной и более меток
    # (localhost, db, redis), IPv4 и IPv6). Схема ограничена 16 символами:
    # реальных схем длиннее нет, а жадная схема с посимвольными откатами на
    # «a.a.a...» давала O(n^2). Из классов пользователя/пароля исключён \x00:
    # пароль, уже заменённый ранним правилом на внутренний маркер \x00s..\x00,
    # не должен попадать в карту подстановок
    ("conn_string", re.compile(
        r"\b([a-z][a-z0-9+.-]{0,15}://[^/@\s:\x00]+:)"
        r"([^@\s\x00]+|\x00s_[0-9a-f]{8}_\d+\x00)(@)"
        r"([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
        r"|\d{1,3}(?:\.\d{1,3}){3}"
        r"|\[[0-9a-fA-F:]+\])"), "conn"),
]


def _junk(rng, length: int) -> str:
    return "".join(rng.choice(_ALNUM) for _ in range(length))


_RE_PREFIX = re.compile(r"^[A-Za-z0-9]{1,6}(?:[-_][A-Za-z0-9]{1,6})*[-_]")
_RE_PREFIX_SHORT = re.compile(r"^[A-Za-z0-9]+[-_]")
# известные фиксированные префиксы без -/_ на конце (раньше терялись)
_KNOWN_PREFIXES = ("AKIA", "ASIA", "AIza")


def _fake_for(real: str) -> str:
    """Фейк той же длины и формы: сохраняет префикс (sk-, ghp_, xoxb-...,
    AKIA/ASIA/AIza) и раскладку разделителей — мусор встаёт ровно на
    альфа-цифровые позиции оригинала, а точки/двоеточия/дефисы/каркас
    «-----BEGIN ...-----» остаются на месте."""
    m = _RE_PREFIX.match(real)
    prefix = m.group(0) if m else ""
    if len(prefix) > 10:
        m2 = _RE_PREFIX_SHORT.match(real)
        prefix = m2.group(0) if m2 else ""
    if not prefix and real[:4] in _KNOWN_PREFIXES:
        prefix = real[:4]
    rng = det_rng("secret", real)
    if "\n" in real:
        return "".join(rng.choice(_ALNUM) if ch.isalnum() else ch for ch in real)
    n_alnum = (sum(1 for ch in real if ch.isalnum())
               - sum(1 for ch in prefix if ch.isalnum()))
    it = iter(_junk(rng, n_alnum))
    return "".join(
        ch if i < len(prefix) or not ch.isalnum() else next(it)
        for i, ch in enumerate(real)
    )


def _kv_secret_like(value: str) -> bool:
    """Похоже на секрет: в значении есть цифра или спецсимвол. Чисто буквенные
    значения — почти всегда проза («token: authentication failed for user»),
    а не пароль."""
    return any(not ch.isalnum() for ch in value) or any(ch.isdigit() for ch in value)


def _fake_host(host: str) -> str:
    """Фейк-хост: IP-адреса заменяются фейковыми IP, домены — example.com."""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        rng = det_rng("ip", host)
        o = [int(p) for p in parts]
        if o[0] == 10:
            return f"10.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        if o[0] == 127:
            return f"127.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        if o[0] == 192 and o[1] == 168:
            return f"192.168.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        if o[0] == 172 and 16 <= o[1] <= 31:
            return f"172.{rng.randrange(16, 32)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        if o[0] == 169 and o[1] == 254:
            return f"169.254.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        base = rng.choice(["192.0.2.", "198.51.100.", "203.0.113."])
        return base + str(rng.randrange(1, 255))
    if host.startswith("[") and host.endswith("]"):
        code = hashlib.sha256(host.encode()).hexdigest()[:4]
        return f"[2001:db8::{code}]"
    code = hashlib.sha256(host.encode()).hexdigest()[:8]
    labels = host.split(".")
    if len(labels) >= 3:
        return f"{labels[0]}.{code}.example.com"
    return f"{code}.example.com"


def apply(s: str, anon) -> str:
    """Маскировка секретов. Вместо фейка в текст ставится маркер \x00sN\x00,
    раскрывается в конце sanitize_string: иначе фейк-пароль в
    postgres://user:FAKE@host маскировался бы повторно как e-mail. В карту
    попадает ровно заменённый фрагмент (значение без метки)."""
    for _name, regex, mode in RULES:
        def repl(m: re.Match, _mode=mode) -> str:
            if _mode == "token":
                whole = m.group(0)
                value = m.group(1)
                kept = whole[:whole.index(value)]
            elif _mode in ("conn", "kv"):
                value = m.group(2)
            else:
                value = m.group(0)
            if _mode == "kv" and not _kv_secret_like(value):
                return m.group(0)  # проза после метки, не секрет
            # пароль conn-string уже заменён ранним правилом на внутренний
            # маркер: не подменяем его (иначе в карту попал бы маркер и
            # обратная подстановка возвращала мусор), маскируем только хост
            premarked = _mode == "conn" and "\x00" in value
            if premarked:
                fake_value = ""
            else:
                fake_value = _fake_for(value) if anon.fake else PLACEHOLDER
                anon._record(value, fake_value)
            anon.stats["secrets"] = anon.stats.get("secrets", 0) + 1
            if _mode == "token":
                return kept + anon._secret_mark(fake_value)
            if _mode == "kv":
                mark = anon._secret_mark(fake_value)
                return m.group(1) + mark + (m.group(3) or "")
            if _mode == "conn":
                host = m.group(4)
                fake_host = _fake_host(host) if anon.fake else "[DOMAIN]"
                anon._record(host, fake_host)
                middle = value if premarked else anon._secret_mark(fake_value)
                return m.group(1) + middle + m.group(3) + anon._secret_mark(fake_host)
            return anon._secret_mark(fake_value)
        s = regex.sub(repl, s)
    return s
