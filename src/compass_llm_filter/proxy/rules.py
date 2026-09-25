"""Рабочее состояние прокси: настройки, правила, аудит.

По умолчанию всё в памяти одного процесса. COMPASS_STATE_FILE сохраняет
настройки и правила через рестарт: пишется при каждом изменении, читается
при старте поверх env-значений.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
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
# группа с альтернативами под квантификатором: перекрывающиеся варианты
# (a|aa)+ дают экспоненциальный возврат без единого квантификатора внутри
DANGEROUS_ALT = re.compile(
    r"\((?:\?[a-zA-Z0-9_:=!<>]+)?[^()|]*\|[^()]*\)\s*(\+|\*|\{\d+,\d*\})"
)


class RuleInputTooLong(Exception):
    """Строка длиннее лимита применения кастомных правил: на мегабайтных
    текстах даже прошедший валидацию паттерн может узреть полиномиальный
    возврат — гарантируть маскировку нельзя, вызов обязан уйти в fail-политику."""


class DuplicateRuleError(ValueError):
    """Правило с таким id уже существует: эндпоинт отображает это в 409 Conflict
    (наследуем ValueError, чтобы загрузка файла состояния просто пропускала дубли)."""


MAX_RULE_INPUT_CHARS = 256 * 1024


def _has_nested_quantified_group(pattern: str) -> bool:
    """Статический сканер структуры: группа, стоящая под квантификатором
    (+, *, ?, {n,m}), внутри которой лежит другая группа — квантифицированная
    или содержащая квантификатор внутри себя. Примеры: ((a+)[ab])*,
    (([а-я]+)[а-я ])* — комбинаторный взрыв возвратов, причём по алфавиту,
    которого нет в зондах; такие паттерны запрещаем сразу, без прогонов."""
    n = len(pattern)
    # (открытие, закрытие, под_квантификатором, есть_квантификатор_внутри)
    closed: list[tuple[int, int, bool, bool]] = []
    stack: list[list] = []   # [открытие, под_квантификатором=False, есть_квант_внутри=False]
    i = 0
    while i < n:
        ch = pattern[i]
        if ch == "\\":                       # экранированный литерал \( \) \[ \+
            i += 2
            continue
        if ch == "[":                        # символьный класс: парены внутри — литералы
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":  # ведущий "]" — литерал
                i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
            continue
        if ch == "(":
            stack.append([i, False, False])
            if i + 1 < n and pattern[i + 1] == "?":
                i += 1                       # "?": маркер конструкции (?: (?= (?< — не квантификатор
            i += 1
            continue
        if ch == ")" and stack:
            start, _, hasq = stack.pop()
            j = i + 1
            followed = (
                j < n and pattern[j] in "+*?"              # ленивые/жадные +? *? — всё равно квантификатор
                or j < n and pattern[j] == "{"
                and re.fullmatch(r"\{\d+(,\d*)?\}",
                                 pattern[j:pattern.find("}", j) + 1] or "x")
            )
            # любая вложенная группа с квантификатором под внешней
            # квантифицированной группой — опасная вложенность
            if followed and any(
                    start < c_start < c_end < i and (c_followed or c_hasq)
                    for c_start, c_end, c_followed, c_hasq in closed):
                return True
            closed.append((start, i, followed, hasq or followed))
            i += 1
            continue
        if ch in "+*?":
            for frame in stack:              # квантификатор лежит внутри всех открытых групп
                frame[2] = True
        elif ch == "{":
            k = pattern.find("}", i)
            if k != -1 and re.fullmatch(r"\{\d+(,\d*)?\}", pattern[i:k + 1]):
                for frame in stack:
                    frame[2] = True
                i = k + 1
                continue
        i += 1
    return False


# зондовый прогон выполняется в дочернем процессе: даже прогрев зонда с
# катастрофическим паттерном никогда не возвращается, watchdog по timeout
# обязан убить его и отвергнуть паттерн, а не повесить сервис
_PROBE_SCRIPT = """\
import json, re, sys, time
compiled = re.compile(sys.argv[1])
alphabets = json.loads(sys.argv[2])
result = []
for alphabet in alphabets:
    row = []
    for n in (20, 60, 200):
        s = alphabet * n + "!"
        t0 = time.perf_counter(); compiled.search(s)               # прогрев
        t1 = time.perf_counter(); compiled.search(s); t2 = time.perf_counter()
        row.append(t2 - t1)
    result.append(row)
print(json.dumps(result))
"""

# латиница, цифры, пробел и кириллица — и СМЕШАННЫЕ повторы: паттерн вида
# ((a|a)b)+c не взрывается ни на одном односимвольном алфавите (нет пары
# «a»+«b»), но на «ababab…» даёт экспоненту 2^n. Без смешанных зондов такой
# паттерн проходил валидацию и вешал применение правила в event loop.
_PROBE_ALPHABETS = ("a", "1", " ", "а", "ab", "a1", "10", "1a")
_PROBE_TIMEOUT_S = 3.0


def validate_safe_regex(pattern: str) -> None:
    """Защита от ReDoS (catastrophic backtracking): проверка структуры квантификаторов
    и тестовый прогон на повторяющихся строках (в дочернем процессе с watchdog)."""
    if not pattern:
        raise ValueError("pattern is required")
    if len(pattern) > 300:
        raise ValueError("pattern too long (max 300 characters)")
    if DANGEROUS_NESTED.search(pattern) or DANGEROUS_ALT.search(pattern):
        raise ValueError("potentially vulnerable regex (nested quantifiers detected)")
    if _has_nested_quantified_group(pattern):
        raise ValueError("potentially vulnerable regex (nested quantifiers detected)")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    del compiled  # компиляция проверена; дочерний процесс компилирует свою

    # цепочка зондов 20 -> 60 -> 200 в дочернем процессе: короткие ловят
    # быстрые взрывы, длинные — медленный рост; отношение t(200)/t(20)
    # отсекает суперлинейные паттерны, а timeout возвращает управление даже
    # с паттерна, который не возвращается вовсе
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _PROBE_SCRIPT, pattern, json.dumps(_PROBE_ALPHABETS)],
            capture_output=True, text=True, timeout=_PROBE_TIMEOUT_S)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("regex execution timeout (catastrophic backtracking risk)") from exc
    except OSError as exc:
        raise ValueError(f"regex probe failed to run: {exc}") from exc
    if proc.returncode != 0:
        raise ValueError("regex probe crashed (catastrophic backtracking risk)")
    try:
        times = json.loads(proc.stdout)
    except ValueError:
        raise ValueError("regex probe produced no result (catastrophic backtracking risk)")
    for row in times:
        base = None
        for dt in row:
            if dt > 0.05:
                raise ValueError("regex execution timeout (catastrophic backtracking risk)")
            # пол базы 100мкс: на реальном суперлинейном росте dt(200) уходит
            # за миллисекунды и легко превышает x50, а шум таймера на
            # микросекундных прогонах ложных срабатываний не даёт
            if base is None:
                base = max(dt, 1e-4)
            elif dt / base > 50:
                raise ValueError("superlinear regex growth (catastrophic backtracking risk)")


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
        # frozenset для O(1)-проверки на каждый запрос
        self.disable_thinking_models = frozenset(
            m.strip() for m in settings.disable_thinking_models.split(",") if m.strip()
        )
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
        rule_id = data.get("id") or uuid.uuid4().hex[:8]
        # id попадает в DOM консоли (inline-onclick) — только безопасный алфавит
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rule_id):
            raise ValueError("id must match [A-Za-z0-9_-]{1,64}")
        if rule_id in self.rules:
            raise DuplicateRuleError(f"rule id {rule_id!r} already exists")
        # name/placeholder попадают в словарь подстановок и ответы консоли:
        # пустой плейсхолдер становился ключом "" в reverse_map и дублировал
        # оригинал между каждым символом каждого ответа; не-строка ломала
        # de_anonymize TypeError'ом
        name = data.get("name") or pattern[:40]
        if not isinstance(name, str) or not 1 <= len(name) <= 200:
            raise ValueError("name must be a string of 1..200 characters")
        placeholder = data.get("placeholder", "[CUSTOM]")
        if not isinstance(placeholder, str) or not 1 <= len(placeholder) <= 200:
            raise ValueError("placeholder must be a string of 1..200 characters")
        rule = CustomRule(
            id=rule_id,
            name=name,
            pattern=pattern,
            replacement=replacement,
            placeholder=placeholder,
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
