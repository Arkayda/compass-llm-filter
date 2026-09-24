"""Счётчики в формате Prometheus text — без внешних зависимостей."""
from __future__ import annotations

from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
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
            lines.append(f"{metric} {self._counters[key]:g}")
        return "\n".join(lines) + "\n"
