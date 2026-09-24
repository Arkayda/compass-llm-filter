"""Счётчики в формате Prometheus text — без внешних зависимостей."""
from __future__ import annotations

from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)

    @staticmethod
    def _escape_label(value: str) -> str:
        """Экранирование значения label по текстовому формату Prometheus:
        бэкслеш, кавычка и перевод строки ломают разбор строки."""
        return (value.replace("\\", "\\\\").replace('"', '\\"')
                .replace("\n", "\\n"))

    @staticmethod
    def _format_value(value: float) -> str:
        """Целые значения — plain int: формат :g отдаёт 1e+06 для 1_000_000,
        и парсер консоли такие значения молча терял."""
        if value == int(value):
            return str(int(value))
        return repr(value)

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        if labels:
            label_str = ",".join(
                f'{k}="{self._escape_label(str(v))}"' for k, v in sorted(labels.items()))
            self._counters[f"{name}{{{label_str}}}"] += value
        else:
            self._counters[name] += value

    def render(self) -> str:
        lines = []
        seen_types: set[str] = set()
        for key in sorted(self._counters):
            name, _, label_part = key.partition("{")
            # одна строка # TYPE на семейство: дубликаты ломают scrape Prometheus
            if name not in seen_types:
                seen_types.add(name)
                lines.append(f"# TYPE {name} counter")
            label_part = label_part.rstrip("}")
            metric = f"{name}{{{label_part}}}" if label_part else name
            lines.append(f"{metric} {self._format_value(self._counters[key])}")
        return "\n".join(lines) + "\n"
