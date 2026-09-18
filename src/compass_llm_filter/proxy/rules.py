"""Рабочее состояние прокси: настройки, правила, аудит.

По умолчанию всё в памяти одного процесса. COMPASS_STATE_FILE сохраняет
настройки и правила через рестарт: пишется при каждом изменении, читается
при старте поверх env-значений.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

from compass_llm_filter.core.validators import det_rng
from compass_llm_filter.core.secrets import _RE_PREFIX, _RE_PREFIX_SHORT, _junk
from compass_llm_filter.proxy.config import Settings


@dataclass
class CustomRule:
    id: str
    name: str
    pattern: str
    replacement: str = "placeholder"   # placeholder | fake
    placeholder: str = "[CUSTOM]"
    enabled: bool = True
    _regex: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._regex = re.compile(self.pattern)

    def apply(self, s: str, anon) -> str:
        def repl(m: re.Match) -> str:
            real = m.group(0)
            if self.replacement == "fake":
                # фейк той же длины, префикс сохраняем (ORD-123456 -> ORD-Q8yVn2)
                rng = det_rng("custom", self.id, real)
                pm = _RE_PREFIX.match(real)
                prefix = pm.group(0) if pm else ""
                if len(prefix) > 10:
                    pm2 = _RE_PREFIX_SHORT.match(real)
                    prefix = pm2.group(0) if pm2 else ""
                fake = prefix + _junk(rng, len(real) - len(prefix))
            else:
                fake = self.placeholder
            anon._record(real, fake)
            anon.stats["custom"] = anon.stats.get("custom", 0) + 1
            return fake
        return self._regex.sub(repl, s)

    def public(self) -> dict:
        return {
            "id": self.id, "name": self.name, "pattern": self.pattern,
            "replacement": self.replacement, "placeholder": self.placeholder,
            "enabled": self.enabled,
        }


DANGEROUS_NESTED = re.compile(
    r"\((?:\?[a-zA-Z0-9_:=!<>]+)?[^)]*(\+|\*|\?|\{\d+,?\d*\})[^)]*\)\s*(\+|\*|\{\d+,?\d*\})"
)


def validate_safe_regex(pattern: str) -> None:
    """Защита от ReDoS (catastrophic backtracking): проверка структуры квантификаторов
    и тестовый прогон на повторяющихся строках."""
    if not pattern:
        raise ValueError("pattern is required")
    if len(pattern) > 300:
        raise ValueError("pattern too long (max 300 characters)")
    if DANGEROUS_NESTED.search(pattern):
        raise ValueError("potentially vulnerable regex (nested quantifiers detected)")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    for s in ("a" * 18 + "!", "1" * 18 + "!", " " * 18 + "!"):
        t0 = time.perf_counter()
        compiled.search(s)
        if time.perf_counter() - t0 > 0.015:
            raise ValueError("regex execution timeout (catastrophic backtracking risk)")


class State:
    """Настройки (меняются через API), правила, аудит, метрики."""

    _SETTING_VALUES = {
        "mode": ("enforce", "detect"),
        "fail_mode": ("closed", "open"),
        "anonymization_mode": ("fake", "placeholders"),
    }

    def __init__(self, settings: Settings):
        self.settings = settings
        self.mode = settings.mode
        self.fail_mode = settings.fail_mode
        self.anonymization_mode = settings.anonymization_mode
        self.rules: dict[str, CustomRule] = {}
        self.audit: deque[dict] = deque(maxlen=settings.audit_max_entries)
        if settings.custom_rules_file:
            self._load_rules_file(settings.custom_rules_file)
        if settings.state_file:
            self._load_state_file(settings.state_file)

    def _load_rules_file(self, path: str) -> None:
        with open(path, encoding="utf-8") as f:
            for item in json.load(f):
                self.add_rule(item)

    def _load_state_file(self, path: str) -> None:
        """Настройки и правила из файла состояния."""
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        for key, allowed in self._SETTING_VALUES.items():
            value = (data.get("settings") or {}).get(key)
            if value in allowed:
                setattr(self, key, value)
        for item in data.get("rules") or []:
            try:
                self.add_rule(item)
            except ValueError:
                continue

    def save_state(self) -> None:
        """Записать состояние в файл. Ошибки IO не роняют запрос: в памяти
        всё уже изменено, рестарт вернёт прежние значения."""
        if not self.settings.state_file:
            return
        data = {
            "settings": self.public_settings(),
            "rules": [r.public() for r in self.rules.values()],
        }
        tmp = self.settings.state_file + ".tmp"
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.settings.state_file)
        except OSError:
            pass

    def add_rule(self, data: dict) -> CustomRule:
        pattern = data.get("pattern") or ""
        validate_safe_regex(pattern)
        replacement = data.get("replacement", "placeholder")
        if replacement not in ("placeholder", "fake"):
            raise ValueError("replacement must be placeholder|fake")
        rule = CustomRule(
            id=data.get("id") or uuid.uuid4().hex[:8],
            name=data.get("name") or pattern[:40],
            pattern=pattern,
            replacement=replacement,
            placeholder=data.get("placeholder", "[CUSTOM]"),
            enabled=bool(data.get("enabled", True)),
        )
        self.rules[rule.id] = rule
        return rule

    def audit_push(self, **entry) -> None:
        self.audit.append({"ts": time.time(), **entry})

    def public_settings(self) -> dict:
        return {
            "mode": self.mode,
            "fail_mode": self.fail_mode,
            "anonymization_mode": self.anonymization_mode,
        }
