"""Конфигурация из переменных окружения (префикс COMPASS_).

Env задаёт стартовые значения; рабочие настройки живут в State и меняются
через PUT /v1/settings без перезапуска.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    upstream_base_url: str = ""
    mode: str = "enforce"            # enforce | detect (shadow)
    fail_mode: str = "closed"        # closed = ошибка маскирования → 503; open = пропуск
    anonymization_mode: str = "fake"  # fake | placeholders
    host: str = "0.0.0.0"
    port: int = 8080
    metrics_enabled: bool = True
    audit_max_entries: int = 1000
    max_body_bytes: int = 10 * 1024 * 1024
    entities_header: str = "x-compass-entities"
    custom_rules_file: str = ""      # опционально: файл со своими правилами при старте
    state_file: str = ""             # опционально: JSON-файл состояния (настройки+правила)
    auth_user: str = ""              # basic-auth консоли/управляющего API (оба или ничего)
    auth_password: str = ""
    secret_pepper: str = ""          # серверная соль ГПСЧ для защиты от rainbow-table подбора
    strict_auth: bool = False        # требовать обязательную настройку basic-auth при старте
    allow_private_upstream: bool = False  # разрешить внутренние IP апстрима (локальный мок/dev)

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        s = cls(
            upstream_base_url=env.get("COMPASS_UPSTREAM_BASE_URL", "").rstrip("/"),
            mode=env.get("COMPASS_MODE", "enforce").strip().lower(),
            fail_mode=env.get("COMPASS_FAIL_MODE", "closed").strip().lower(),
            anonymization_mode=env.get("COMPASS_ANONYMIZATION_MODE", "fake").strip().lower(),
            host=env.get("COMPASS_HOST", "0.0.0.0"),
            port=int(env.get("COMPASS_PORT", "8080")),
            # единый набор значений с остальными флагами; незаданная или
            # пустая переменная — метрики ВКЛЮЧЕНЫ (прежний дефолт)
            metrics_enabled=(env.get("COMPASS_METRICS_ENABLED") or "true").strip().lower()
            in ("true", "1", "yes"),
            audit_max_entries=int(env.get("COMPASS_AUDIT_MAX_ENTRIES", "1000")),
            max_body_bytes=int(env.get("COMPASS_MAX_BODY_BYTES", str(10 * 1024 * 1024))),
            entities_header=env.get("COMPASS_ENTITIES_HEADER", "x-compass-entities").lower(),
            custom_rules_file=env.get("COMPASS_CUSTOM_RULES_FILE", ""),
            state_file=env.get("COMPASS_STATE_FILE", ""),
            auth_user=env.get("COMPASS_AUTH_USER", ""),
            auth_password=env.get("COMPASS_AUTH_PASSWORD", ""),
            secret_pepper=env.get("COMPASS_SECRET_PEPPER", ""),
            strict_auth=env.get("COMPASS_STRICT_AUTH", "false").lower() in ("true", "1", "yes"),
            allow_private_upstream=env.get("COMPASS_ALLOW_PRIVATE_UPSTREAM", "false").lower()
            in ("true", "1", "yes"),
        )
        if s.mode not in ("enforce", "detect"):
            raise ValueError(f"COMPASS_MODE must be enforce|detect, got {s.mode!r}")
        if s.fail_mode not in ("closed", "open"):
            raise ValueError(f"COMPASS_FAIL_MODE must be closed|open, got {s.fail_mode!r}")
        if s.anonymization_mode not in ("fake", "placeholders"):
            raise ValueError(
                f"COMPASS_ANONYMIZATION_MODE must be fake|placeholders, got {s.anonymization_mode!r}")
        if not s.upstream_base_url:
            raise ValueError("COMPASS_UPSTREAM_BASE_URL is required")
        return s
