"""Фазы российских идентификаторов: карты, СНИЛС, ИНН, ОГРН/ОГРНИП, паспорта.

Каждая фаза сначала находит кандидат по формату (длине и разделителям), затем
проверяет контрольную сумму — так номер договора или unixtime с тем же числом
цифр не превращается в «СНИЛС». Валидные значения заменяются детерминированными
фейками той же формы, у фейков контрольные суммы тоже валидны (модель не
спотыкается о заведомо битые номера). Разделители (пробел/дефис/их отсутствие)
сохраняются.

Порядок в конвейере: ДО телефонной фазы — иначе СНИЛС/ИНН/ОГРН из 11–13 цифр
матчатся как телефоны. Не прошедшие контрольную сумму кандидаты остаются тексту
и, если похожи на телефон, обрабатываются телефонной фазой как раньше.
"""
from __future__ import annotations

import re

from compass_llm_filter.core.validators import (
    det_rng, inn10_check, inn12_check, inn_ok, luhn_check_digit, luhn_ok,
    ogrn_check, ogrn_ok, ogrnip_check, snils_check_digits, snils_ok,
)

# (?<!\d)/(?!\d): не отрывать куски от более длинных цифровых цепочек
RE_CARD = re.compile(r"(?<!\d)\d{4}(?:[ \-]?\d{4}){3}(?!\d)")
RE_SNILS = re.compile(r"(?<!\d)\d{3}(?:[ \-]?\d{3})(?:[ \-]?\d{3})(?:[ \-]?\d{2})(?!\d)")
RE_OGRNIP = re.compile(r"(?<!\d)\d{15}(?!\d)")
RE_OGRN = re.compile(r"(?<!\d)\d{13}(?!\d)")
RE_INN12 = re.compile(r"(?<!\d)\d{12}(?!\d)")
RE_INN10 = re.compile(r"(?<!\d)\d{10}(?!\d)")
# паспорт РФ: серия 4 цифры + пробел + номер 6 цифр (без контрольной суммы,
# поэтому только явная форма с пробелом)
RE_PASSPORT = re.compile(r"(?<!\d)\d{4} \d{6}(?!\d)")


def _keep_layout(original: str, digits: str) -> str:
    """Вставить новые цифры в исходную раскладку (пробелы/дефисы на месте)."""
    it = iter(digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in original)


def fake_card(original: str, digits: str) -> str:
    rng = det_rng("card", digits)
    prefix = "4" + "".join(rng.choice("0123456789") for _ in range(14))
    return _keep_layout(original, prefix + luhn_check_digit(prefix))


def fake_snils(original: str, digits: str) -> str:
    rng = det_rng("snils", digits)
    number9 = "".join(rng.choice("0123456789") for _ in range(9))
    return _keep_layout(original, number9 + snils_check_digits(number9))


def fake_inn10(original: str, digits: str) -> str:
    rng = det_rng("inn10", digits)
    number9 = rng.choice("123456789") + "".join(rng.choice("0123456789") for _ in range(8))
    return _keep_layout(original, number9 + inn10_check(number9))


def fake_inn12(original: str, digits: str) -> str:
    rng = det_rng("inn12", digits)
    number10 = rng.choice("123456789") + "".join(rng.choice("0123456789") for _ in range(9))
    return _keep_layout(original, number10 + inn12_check(number10))


def fake_ogrn(original: str, digits: str) -> str:
    rng = det_rng("ogrn", digits)
    number12 = rng.choice("123456789") + "".join(rng.choice("0123456789") for _ in range(11))
    return _keep_layout(original, number12 + ogrn_check(number12))


def fake_ogrnip(original: str, digits: str) -> str:
    rng = det_rng("ogrnip", digits)
    number14 = rng.choice("123456789") + "".join(rng.choice("0123456789") for _ in range(13))
    return _keep_layout(original, number14 + ogrnip_check(number14))


def fake_number(original: str, digits: str) -> str:
    """Паспорт: контрольной суммы нет — просто другие цифры той же длины."""
    rng = det_rng("passport", digits)
    fake = "".join(rng.choice("0123456789") for _ in digits)
    return _keep_layout(original, fake)


# (стат-ключ, regex, валидатор цифр, генератор фейка, плейсхолдер)
RULES = [
    ("cards", RE_CARD, luhn_ok, fake_card, "[CARD]"),
    ("snils", RE_SNILS, snils_ok, fake_snils, "[SNILS]"),
    ("ogrnips", RE_OGRNIP, ogrn_ok, fake_ogrnip, "[OGRNIP]"),
    ("ogrns", RE_OGRN, ogrn_ok, fake_ogrn, "[OGRN]"),
    ("inns12", RE_INN12, inn_ok, fake_inn12, "[INN]"),
    ("inns", RE_INN10, inn_ok, fake_inn10, "[INN]"),
    ("passports", RE_PASSPORT, lambda d: True, fake_number, "[PASSPORT]"),
]


def apply(s: str, anon) -> str:
    """Прогнать текст по всем RU-PII правилам через данный Anonymizer."""
    for stat_key, regex, validate, make_fake, placeholder in RULES:
        def repl(m: re.Match, _v=validate, _f=make_fake, _p=placeholder, _k=stat_key) -> str:
            original = m.group(0)
            digits = "".join(ch for ch in original if ch.isdigit())
            if not _v(digits):
                return original  # не прошла контрольную сумму — не наш идентификатор
            fake_value = _f(original, digits) if anon.fake else _p
            anon._record(original, fake_value)
            anon.stats[_k] = anon.stats.get(_k, 0) + 1
            return fake_value
        s = regex.sub(repl, s)
    return s
