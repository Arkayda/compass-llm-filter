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
    # приватные ключи: маркер начала блока
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----"), "whole"),
    # OpenAI и совместимые
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"), "whole"),
    # GitHub tokens
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), "whole"),
    ("github_app", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "whole"),
    # AWS access keys
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "whole"),
    # Google API
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "whole"),
    # Slack
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"), "whole"),
    # Telegram bot API
    ("tg_bot_key", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"), "whole"),
    # Stripe
    ("stripe_key", re.compile(r"\b[spkr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), "whole"),
    # GLM / BigModel: id HEX32 + '.' + пароль
    ("glm_key", re.compile(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{10,20}\b"), "whole"),
    # JWT (три base64url-сегмента, ey..-заголовок)
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b"), "whole"),
    # Bearer <токен>
    ("bearer", re.compile(r"\b[Bb]earer ([A-Za-z0-9._~+/=-]{20,})"), "token"),
    # пары ключ=значение: метку сохраняем, значение меняем
    ("kv_secret", re.compile(
        r"(?i)\b((?:api[-_]?key|apikey|access[-_]?token|secret|password|passwd|pwd|token)"
        r"\s*[:=]\s*[\"']?)([A-Za-z0-9+/_=-]{12,})([\"']?)"), "kv"),
    # connection string: scheme://user:PASSWORD@HOST; хост отдельной группой —
    # доменная фаза домены после @ не трогает (часть e-mail), а хост БД
    # утечь не должен
    ("conn_string", re.compile(
        r"\b([a-z][a-z0-9+.-]*://[^/@\s:]+:)([^@\s]+)(@)"
        r"([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,14})"), "conn"),
]


def _junk(rng, length: int) -> str:
    return "".join(rng.choice(_ALNUM) for _ in range(length))


_RE_PREFIX = re.compile(r"^[A-Za-z0-9]{1,6}(?:[-_][A-Za-z0-9]{1,6})*[-_]")
_RE_PREFIX_SHORT = re.compile(r"^[A-Za-z0-9]+[-_]")


def _fake_for(real: str) -> str:
    """Фейк той же длины с сохранением префикса (sk-, ghp_, xoxb-...)."""
    m = _RE_PREFIX.match(real)
    prefix = m.group(0) if m else ""
    if len(prefix) > 10:
        m2 = _RE_PREFIX_SHORT.match(real)
        prefix = m2.group(0) if m2 else ""
    return prefix + _junk(det_rng("secret", real), len(real) - len(prefix))


def _fake_host(host: str) -> str:
    """Фейк-хост в стиле доменной фазы."""
    code = hashlib.sha256(host.lower().encode()).hexdigest()[:8]
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
            elif _mode == "conn":
                value = m.group(2)
            elif _mode == "kv":
                value = m.group(2)
            else:
                value = m.group(0)
            fake_value = _fake_for(value) if anon.fake else PLACEHOLDER
            anon._record(value, fake_value)
            anon.stats["secrets"] = anon.stats.get("secrets", 0) + 1
            mark = anon._secret_mark(fake_value)
            if _mode == "token":
                return kept + mark
            if _mode == "kv":
                return m.group(1) + mark + (m.group(3) or "")
            if _mode == "conn":
                host = m.group(4)
                fake_host = _fake_host(host) if anon.fake else "[DOMAIN]"
                anon._record(host, fake_host)
                return m.group(1) + mark + m.group(3) + anon._secret_mark(fake_host)
            return mark
        s = regex.sub(repl, s)
    return s
