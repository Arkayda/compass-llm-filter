"""Контрольные суммы российских идентификаторов и карт + детерминированный ГПСЧ.

Проверки — чистые функции над строкой: отличают настоящие СНИЛС/ИНН/ОГРН/карты
от случайных чисел той же длины. IBAN — по ISO 13616 (mod 97).
"""
from __future__ import annotations

import hashlib
import os
import random
import re

DEFAULT_PEPPER = os.environ.get("COMPASS_SECRET_PEPPER", "")


def set_default_pepper(pepper: str) -> None:
    """Установить глобальный серверный секрет (pepper) для ГПСЧ."""
    global DEFAULT_PEPPER
    DEFAULT_PEPPER = pepper


def det_rng(*parts, pepper: str | None = None) -> random.Random:
    """Детерминированный ГПСЧ: seed = SHA256 от склеенных частей с солью (pepper),
    одинаковым входам всегда одинаковые выходы."""
    p = DEFAULT_PEPPER if pepper is None else pepper
    prefix = [f"pepper:{p}"] if p else []
    seed = hashlib.sha256("|".join(prefix + [str(part) for part in parts]).encode("utf-8")).hexdigest()
    return random.Random(seed)


def fake_digits(digits: str, extra: int = 0) -> str:
    """Другие цифры той же длины, первая не 0."""
    fake = digits
    for attempt in range(extra, extra + 64):
        rng = det_rng("digits", digits, attempt)
        first = rng.choice("123456789")
        fake = first + "".join(rng.choice("0123456789") for _ in range(len(digits) - 1))
        if fake != digits:
            break
    return fake


def luhn_ok(digits: str) -> bool:
    """Алгоритм Луна для банковских карт (и других 16-значных номеров)."""
    if len(digits) < 12 or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(prefix: str) -> str:
    """Контрольная цифра Луна для дополнения prefix до валидного номера."""
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = int(ch)
        if i % 2 == 0:  # позиция контрольной цифры
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def snils_ok(digits: str) -> bool:
    """СНИЛС: 9 цифр номера + 2 контрольные. Контроль: сумма номер*вес (9..1);
    <100 → равна сумме; 100/101 → 00; иначе сумма % 101."""
    if len(digits) != 11 or not digits.isdigit():
        return False
    number, check = digits[:9], int(digits[9:])
    total = sum(int(d) * (9 - i) for i, d in enumerate(number))
    if total < 100:
        expected = total
    elif total in (100, 101):
        expected = 0
    else:
        expected = total % 101
    return check == expected


def snils_check_digits(number9: str) -> str:
    total = sum(int(d) * (9 - i) for i, d in enumerate(number9))
    if total < 100:
        return f"{total:02d}"
    if total in (100, 101):
        return "00"
    check = total % 101
    if check > 99:  # 100 не помещается в две контрольные цифры — СНИЛС с такой суммой не существует
        return "100"
    return f"{check:02d}"


INN10_W = (2, 4, 10, 3, 5, 9, 4, 6, 8)
INN12_W1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
INN12_W2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)


def _weighted(digits: str, weights: tuple[int, ...]) -> int:
    return sum(int(d) * w for d, w in zip(digits, weights)) % 11 % 10


def inn_ok(digits: str) -> bool:
    """ИНН юридического лица (10 цифр) или ИП (12 цифр)."""
    if len(digits) == 10 and digits.isdigit():
        return _weighted(digits[:9], INN10_W) == int(digits[9])
    if len(digits) == 12 and digits.isdigit():
        return (_weighted(digits[:10], INN12_W1) == int(digits[10])
                and _weighted(digits[:11], INN12_W2) == int(digits[11]))
    return False


def inn10_check(number9: str) -> str:
    return str(_weighted(number9, INN10_W))


def inn12_check(number10: str) -> str:
    """Контрольные цифры ИП: первая по первым 10 цифрам, вторая по 11."""
    n11 = str(_weighted(number10, INN12_W1))
    n12 = str(_weighted(number10 + n11, INN12_W2))
    return n11 + n12


def ogrn_ok(digits: str) -> bool:
    """ОГРН юрлица (13 цифр, контроль = первые 12 % 11 % 10)
    и ОГРНИП (15 цифр, контроль = первые 14 % 13 % 10)."""
    if len(digits) == 13 and digits.isdigit():
        return int(digits[:12]) % 11 % 10 == int(digits[12])
    if len(digits) == 15 and digits.isdigit():
        return int(digits[:14]) % 13 % 10 == int(digits[14])
    return False


def ogrn_check(number12: str) -> str:
    return str(int(number12) % 11 % 10)


def ogrnip_check(number14: str) -> str:
    return str(int(number14) % 13 % 10)


# --- IBAN ---

IBAN_RE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}")


def _iban_numeric(s: str) -> str:
    """IBAN в виде цепочки цифр для mod 97: буквы -> числа (A=10 .. Z=35)."""
    return "".join(str(int(ch, 36)) for ch in s)


def _mod97(digits: str) -> int:
    """Остаток по 97 без конвертации всей строки в bigint."""
    rem = 0
    for ch in digits:
        rem = (rem * 10 + int(ch)) % 97
    return rem


def iban_ok(value: str) -> bool:
    """IBAN по ISO 13616: первые 4 знака в конец, mod 97 == 1."""
    compact = "".join(ch for ch in value if ch.isalnum()).upper()
    if not IBAN_RE.fullmatch(compact) or not 14 <= len(compact) <= 34:
        return False
    return _mod97(_iban_numeric(compact[4:] + compact[:4])) == 1


def iban_check_digits(country: str, bban: str) -> str:
    """Контрольные цифры: 98 - mod97(BBAN+страна+00)."""
    n = _iban_numeric(bban + country + "00")
    return f"{98 - _mod97(n):02d}"
