"""Идентификаторы: карты, СНИЛС, ИНН, ОГРН/ОГРНИП, паспорта, IBAN.

Кандидат находится по формату, затем проверяется контрольная сумма — номер
договора или unixtime с тем же числом цифр «СНИЛСом» не станет. Валидные
значения заменяются фейками той же формы, у фейков суммы тоже валидны,
разделители сохраняются. Непрошедшие проверку кандидаты остаются тексту и,
если похожи на телефон, маскируются телефонной фазой.
"""
from __future__ import annotations

import re

from compass_llm_filter.core.validators import (
    det_rng, iban_check_digits, iban_ok, inn10_check, inn12_check, inn_ok,
    luhn_check_digit, luhn_ok, ogrn_check, ogrn_ok, ogrnip_check,
    snils_check_digits, snils_ok,
)

# (?<!\d)/(?!\d) — не отрывать куски от более длинных цифровых цепочек
RE_CARD = re.compile(r"(?<!\d)\d{4}(?:[ \-]?\d{4}){3}(?!\d)")
RE_SNILS = re.compile(r"(?<!\d)\d{3}(?:[ \-]?\d{3})(?:[ \-]?\d{3})(?:[ \-]?\d{2})(?!\d)")
RE_OGRNIP = re.compile(r"(?<!\d)\d{15}(?!\d)")
RE_OGRN = re.compile(r"(?<!\d)\d{13}(?!\d)")
RE_INN12 = re.compile(r"(?<!\d)\d{12}(?!\d)")
RE_INN10 = re.compile(r"(?<!\d)\d{10}(?!\d)")
# паспорт: серия (4 цифры) и номер (6 цифр) с пробелом, дефисом или символом №
RE_PASSPORT = re.compile(r"(?<!\d)\d{4}(?:[ \-]| ?№ ?)\d{6}(?!\d)")
# паспорт в явном контексте: 10 цифр слитно после слова «паспорт» / «серия»
RE_PASSPORT_CTX = re.compile(
    r"(?i)\b((?:паспорт\w*|паспортные\s+данные|сери[яи]\s+паспорта)\s*(?:№\s*|:\s*)?)(?<!\d)(\d{10})(?!\d)"
)
# IBAN: страна + 2 контрольные + BBAN группами по 2-4
RE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{2,4}){2,8}\b")


def _keep_layout(original: str, digits: str) -> str:
    """Новые цифры в исходной раскладке (пробелы/дефисы на месте)."""
    it = iter(digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in original)


def _digits_of(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isdigit())


def _alnum_of(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isalnum()).upper()


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
    """Паспорт: суммы нет, просто другие цифры той же длины."""
    rng = det_rng("passport", digits)
    fake = "".join(rng.choice("0123456789") for _ in digits)
    return _keep_layout(original, fake)


def fake_iban(original: str, compact: str) -> str:
    """Валидный IBAN той же страны и длины, раскладка групп сохраняется."""
    country = compact[:2]
    rng = det_rng("iban", compact)
    bban = "".join(rng.choice("0123456789") for _ in compact[4:])
    fake_compact = country + iban_check_digits(country, bban) + bban
    it = iter(fake_compact)
    return "".join(next(it) if ch.isalnum() else ch for ch in original)


# (стат-ключ, regex, экстрактор кандидата, валидатор, генератор фейка, плейсхолдер)
RULES = [
    ("cards", RE_CARD, _digits_of, luhn_ok, fake_card, "[CARD]"),
    ("snils", RE_SNILS, _digits_of, snils_ok, fake_snils, "[SNILS]"),
    ("ogrnips", RE_OGRNIP, _digits_of, ogrn_ok, fake_ogrnip, "[OGRNIP]"),
    ("ogrns", RE_OGRN, _digits_of, ogrn_ok, fake_ogrn, "[OGRN]"),
    ("inns12", RE_INN12, _digits_of, inn_ok, fake_inn12, "[INN]"),
    ("inns", RE_INN10, _digits_of, inn_ok, fake_inn10, "[INN]"),
    ("passports", RE_PASSPORT, _digits_of, lambda d: True, fake_number, "[PASSPORT]"),
    ("passports_ctx", RE_PASSPORT_CTX, _digits_of, lambda d: True, fake_number, "[PASSPORT]"),
    ("ibans", RE_IBAN, _alnum_of, iban_ok, fake_iban, "[IBAN]"),
]


from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from compass_llm_filter.core.anonymizer import Anonymizer

def apply(s: str, anon: Anonymizer, only: tuple = (), skip: tuple = (), mark_late: bool = False) -> str:
    """Прогнать текст по правилам идентификаторов.

    only/skip фильтруют правила по стат-ключу. IBAN идёт отдельным прогоном
    до телефонной фазы и с mark_late=True: его цифровой хвост неотличим от
    телефона, в том числе у уже вставленного фейка.
    """
    for stat_key, regex, extract, validate, make_fake, placeholder in RULES:
        if only and stat_key not in only or stat_key in skip:
            continue

        def repl(m: re.Match, _x=extract, _v=validate, _f=make_fake,
                 _p=placeholder, _k=stat_key) -> str:
            if _k == "passports_ctx":
                prefix = m.group(1)
                original = m.group(2)
                candidate = _x(original)
                fake_value = _f(original, candidate) if anon.fake else _p
                anon.record_substitution(original, fake_value)
                anon.record_stat("passports")
                out = anon.get_secret_mark(fake_value) if mark_late else fake_value
                return prefix + out

            original = m.group(0)
            candidate = _x(original)
            if not _v(candidate):
                return original  # сумма не сошлась — не наш идентификатор
            fake_value = _f(original, candidate) if anon.fake else _p
            anon.record_substitution(original, fake_value)
            anon.record_stat(_k)
            return anon.get_secret_mark(fake_value) if mark_late else fake_value
        s = regex.sub(repl, s)
    return s
