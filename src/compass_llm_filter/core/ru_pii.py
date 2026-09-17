"""Фазы идентификаторов: карты, СНИЛС, ИНН, ОГРН/ОГРНИП, паспорта, IBAN.

Каждая фаза сначала находит кандидата по формату (длине и разделителям), затем
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
    det_rng, iban_check_digits, iban_ok, inn10_check, inn12_check, inn_ok,
    luhn_check_digit, luhn_ok, ogrn_check, ogrn_ok, ogrnip_check,
    snils_check_digits, snils_ok,
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
# IBAN: страна + 2 контрольные + BBAN группами по 2–4, пробелы между группами
RE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{2,4}){2,8}\b")


def _keep_layout(original: str, digits: str) -> str:
    """Вставить новые цифры в исходную раскладку (пробелы/дефисы на месте)."""
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
    """Паспорт: контрольной суммы нет — просто другие цифры той же длины."""
    rng = det_rng("passport", digits)
    fake = "".join(rng.choice("0123456789") for _ in digits)
    return _keep_layout(original, fake)


def fake_iban(original: str, compact: str) -> str:
    """Другой валидный IBAN той же страны и длины; раскладка групп сохраняется."""
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
    ("ibans", RE_IBAN, _alnum_of, iban_ok, fake_iban, "[IBAN]"),
]


def apply(s: str, anon, only: tuple = (), skip: tuple = (), mark_late: bool = False) -> str:
    """Прогнать текст по правилам идентификаторов через данный Anonymizer.

    only/skip фильтруют правила по стат-ключу: IBAN применяется отдельным
    прогоном ДО телефонной фазы (его цифровой хвост неотличим от телефона),
    с mark_late=True фейк ставится поздним маркером — иначе телефонная фаза
    заменит цифры уже вставленного фейка (фейк-IBAN тоже валиден).
    """
    for stat_key, regex, extract, validate, make_fake, placeholder in RULES:
        if only and stat_key not in only or stat_key in skip:
            continue

        def repl(m: re.Match, _x=extract, _v=validate, _f=make_fake,
                 _p=placeholder, _k=stat_key) -> str:
            original = m.group(0)
            candidate = _x(original)
            if not _v(candidate):
                return original  # не прошла контрольную сумму — не наш идентификатор
            fake_value = _f(original, candidate) if anon.fake else _p
            anon._record(original, fake_value)
            anon.stats[_k] = anon.stats.get(_k, 0) + 1
            return anon._secret_mark(fake_value) if mark_late else fake_value
        s = regex.sub(repl, s)
    return s
