"""Рабочее состояние прокси: настройки, кастомные правила, аудит.

Всё в памяти одного процесса — вместе с картой подстановок это часть
проекта: оригиналы не переживают запрос, состояние не переживает
рестарт (свои правила при желании грузятся из файла при старте).
"""
from __future__ import annotations

import json
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
                # фейк той же длины с сохранением распознаваемого префикса
                # (ORD-123456 -> ORD-Q8yVn2)
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


class State:
    """Настройки (меняются через API), правила, аудит, метрики."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.mode = settings.mode
        self.fail_mode = settings.fail_mode
        self.anonymization_mode = settings.anonymization_mode
        self.rules: dict[str, CustomRule] = {}
        self.audit: deque[dict] = deque(maxlen=settings.audit_max_entries)
        if settings.custom_rules_file:
            self._load_rules_file(settings.custom_rules_file)

    def _load_rules_file(self, path: str) -> None:
        with open(path, encoding="utf-8") as f:
            for item in json.load(f):
                self.add_rule(item)

    def add_rule(self, data: dict) -> CustomRule:
        pattern = data.get("pattern") or ""
        if not pattern:
            raise ValueError("pattern is required")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
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
