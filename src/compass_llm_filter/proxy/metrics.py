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
        for key in sorted(self._counters):
            name, _, label_part = key.partition("{")
            label_part = label_part.rstrip("}")
            metric = f"{name}{{{label_part}}}" if label_part else name
            help_name = name.split("{")[0]
            lines.append(f"# TYPE {help_name} counter")
            lines.append(f"{metric} {self._counters[key]:g}")
        return "\n".join(lines) + "\n"
