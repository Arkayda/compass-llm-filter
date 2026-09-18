"""Эвристический детектор попыток Prompt Injection и Jailbreak.

Проверяет пользовательский текст на известные сигнатуры и паттерны:
- Попытки раскрытия/утечки системного промпта (System Prompt Leakage)
- Инструкции отмены предыдущих ограничений ("Ignore previous instructions")
- Ролевые джейлбрейки (DAN, Developer Mode, Unfiltered AI)
- Поддельные системные сообщения ([SYSTEM], <system>, Developer Message:)

Работает исключительно на стандартной библиотеке Python (0 сторонних зависимостей).
"""
from __future__ import annotations

import re

# Паттерны с категориями для точного аудита
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|skip)\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|rules|directions|prompts|commands)\b|"
            r"\b(?:забудь|игнорируй|пропусти|отмени)\s+(?:все\s+)?(?:предыдущие|прошлые|вышестоящие|исходные)\s+(?:инструкции|указания|правила|команды)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_leak",
        re.compile(
            r"\b(?:show|print|reveal|repeat|output|display|give)(?:\s+me)?\s+(?:your\s+)?(?:initial|system|original|developer|internal)\s+(?:prompt|instructions|rules|guidelines|configuration)\b|"
            r"\b(?:what\s+(?:are|were)\s+your\s+(?:original|system|initial|secret)\s+instructions\b)|"
            r"\b(?:repeat\s+(?:all\s+)?(?:the\s+)?text\s+above\b)|"
            r"\b(?:покажи|выведи|напиши|раскрой|повтори)(?:\s+мне)?\s+(?:свой\s+)?(?:системный\s+промпт|начальные\s+инструкции|исходный\s+промпт|системные\s+правила|секретные\s+инструкции)\b|"
            r"\bповтори\s+текст\s+выше\b",
            re.IGNORECASE,
        ),
    ),
    (
        "jailbreak_persona",
        re.compile(
            r"\b(?:DAN\s+mode|Do\s+Anything\s+Now|unfiltered\s+(?:ai|assistant|model|mode)|jailbreak(?:ed)?)\b|"
            r"\b(?:developer|god|unrestricted|sudo)\s+mode\s+(?:enabled|activated|on)\b|"
            r"\b(?:bypass|override|disable)\s+(?:all\s+)?(?:safety|content|ethical|security)\s+(?:filters|guidelines|policies|checks|rules)\b|"
            r"\b(?:режим\s+разработчика\s+(?:включен|активирован)|действуй\s+без\s+(?:цензуры|ограничений|фильтров)|ты\s+теперь\s+без\s+ограничений)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_system_delimiter",
        re.compile(
            r"(?:\[\s*(?:system|developer|admin)(?:\s+instructions)?\s*\])|"
            r"(?:<\s*(?:system|developer|admin|instruction)\s*>)|"
            r"\b(?:system|developer)\s+message:\s*",
            re.IGNORECASE,
        ),
    ),
]


def detect_prompt_injection(text: str) -> list[str]:
    """Проверяет текст на наличие признаков prompt injection / jailbreak.

    Возвращает список идентификаторов обнаруженных угроз (пустой список, если чисто).
    """
    if not text or not isinstance(text, str):
        return []

    detected: list[str] = []
    for category, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            detected.append(category)

    return detected
