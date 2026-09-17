"""Каталог секретов: API-ключи, токены, приватные ключи, пароли в конфигах.

Отдельная категория PII: сами по себе строки не «персональны», но их утечка в
LLM-провайдер недопустима. Правила — про префиксы и формы известных ключей;
для пар присваивания (api_key=..., password:...) заменяется только значение,
метка остаётся читаемой. Замена — детерминированный мусор той же длины/формы,
чтобы модель не теряла структуру текста.
"""
from __future__ import annotations

import re

from compass_llm_filter.core.validators import det_rng

_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
PLACEHOLDER = "[SECRET]"

# режимы: "whole" — заменить весь матч; "token" — группу 1 (метку перед ней
# сохранить, напр. «Bearer »); "kv" — группу 2 между меткой (группа 1) и
# хвостом (группа 3).
# (имя, regex, режим)
RULES: list[tuple[str, re.Pattern, str]] = [
    # приватные ключи: маркер начала блока
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----"), "whole"),
    # OpenAI / совместимые
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
    # пароль в connection string: scheme://user:PASSWORD@host
    ("conn_string", re.compile(r"\b([a-z][a-z0-9+.-]*://[^/@\s:]+:)([^@\s]+)(@)"), "kv"),
]


def _junk(rng, length: int) -> str:
    return "".join(rng.choice(_ALNUM) for _ in range(length))


_RE_PREFIX = re.compile(r"^[A-Za-z0-9]{1,6}(?:[-_][A-Za-z0-9]{1,6})*[-_]")
_RE_PREFIX_SHORT = re.compile(r"^[A-Za-z0-9]+[-_]")


def _fake_for(real: str) -> str:
    """Фейк той же длины с сохранением распознаваемого префикса (sk-, ghp_,
    xoxb-...): модель видит, что это по-прежнему упоминание ключа."""
    m = _RE_PREFIX.match(real)
    prefix = m.group(0) if m else ""
    if len(prefix) > 10:
        m2 = _RE_PREFIX_SHORT.match(real)
        prefix = m2.group(0) if m2 else ""
    return prefix + _junk(det_rng("secret", real), len(real) - len(prefix))


def apply(s: str, anon) -> str:
    for _name, regex, mode in RULES:
        def repl(m: re.Match, _mode=mode) -> str:
            whole = m.group(0)
            if _mode == "token":
                kept, value = whole[:whole.index(m.group(1))], m.group(1)
                fake_value = _fake_for(value) if anon.fake else PLACEHOLDER
                result = kept + fake_value
            elif _mode == "kv":
                label, value, tail = m.group(1), m.group(2), m.group(3) or ""
                fake_value = _fake_for(value) if anon.fake else PLACEHOLDER
                result = label + fake_value + tail
            else:
                result = _fake_for(whole) if anon.fake else PLACEHOLDER
            anon._record(whole, result)
            anon.stats["secrets"] = anon.stats.get("secrets", 0) + 1
            return result
        s = regex.sub(repl, s)
    return s
