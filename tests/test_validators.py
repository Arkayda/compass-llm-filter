"""Тесты контрольных сумм (compass_llm_filter.core.validators)."""
from compass_llm_filter.core import validators as v


def test_luhn_known_cards():
    assert v.luhn_ok("4111111111111111")        # классическая тестовая Visa
    assert v.luhn_ok("5500005555555559")        # тестовая Mastercard
    assert not v.luhn_ok("4111111111111112")
    assert not v.luhn_ok("123")                 # коротко
    assert not v.luhn_ok("4111 1111 1111 1111")  # не цифры — разделители недопустимы


def test_luhn_check_digit_completes_valid():
    prefix = "411111111111111"
    assert v.luhn_ok(prefix + v.luhn_check_digit(prefix))


def test_snils_checksum():
    # 123456789 → взвешенная сумма 165 → 165 % 101 = 64
    assert v.snils_check_digits("123456789") == "64"
    assert v.snils_ok("12345678964")
    assert not v.snils_ok("12345678906")
    assert not v.snils_ok("1234567896")   # 10 цифр
    assert not v.snils_ok("123456789064")  # 12 цифр


def test_snils_edge_zero_check():
    # сумма ровно 100 → контроль «00»: 3*9+2*(8+7+6+5+4+3+2)+3*1 = 100
    number9 = "322222223"
    assert sum(int(d) * (9 - i) for i, d in enumerate(number9)) == 100
    assert v.snils_check_digits(number9) == "00"
    assert v.snils_ok(number9 + "00")


def test_inn10_known_valid():
    assert v.inn_ok("7707083893")      # известный валидный ИНН
    assert not v.inn_ok("7707083894")
    assert not v.inn_ok("770708389")
    assert not v.inn_ok("77070838933")


def test_inn12_known_valid():
    assert v.inn_ok("500100732259")    # известный валидный 12-значный
    assert not v.inn_ok("500100732258")


def test_inn_checks_generate_valid():
    fake9 = "123456789"
    assert v.inn_ok(fake9 + v.inn10_check(fake9))
    fake10 = "1234567890"
    assert v.inn_ok(fake10 + v.inn12_check(fake10))


def test_ogrn_known_valid():
    assert v.ogrn_ok("1027700132195")   # 13 цифр, известный валидный
    assert not v.ogrn_ok("1027700132196")


def test_ogrnip_generated_valid():
    number14 = "30450011600015"
    full = number14 + v.ogrnip_check(number14)
    assert len(full) == 15
    assert v.ogrn_ok(full)
    assert not v.ogrn_ok(number14 + "0" * 14)  # мусорная контрольная


def test_ogrn_generated_valid():
    number12 = "102770013219"
    assert v.ogrn_ok(number12 + v.ogrn_check(number12))


def test_det_rng_deterministic():
    assert v.det_rng("a", 1).random() == v.det_rng("a", 1).random()
    assert v.det_rng("a", 1).random() != v.det_rng("a", 2).random()
    assert v.fake_digits("1234567890") != "1234567890"
    assert len(v.fake_digits("1234567890")) == 10


def test_det_rng_pepper():
    # Без соли и с солью — разные последовательности
    r_plain = v.det_rng("val", 1).random()
    r_pep1 = v.det_rng("val", 1, pepper="secret1").random()
    r_pep2 = v.det_rng("val", 1, pepper="secret2").random()
    assert r_plain != r_pep1
    assert r_pep1 != r_pep2
    # Одинаковая соль — одинаковый результат
    assert v.det_rng("val", 1, pepper="secret1").random() == r_pep1

    # Глобальная соль
    v.set_default_pepper("global_secret")
    try:
        assert v.det_rng("val", 1).random() == v.det_rng("val", 1, pepper="global_secret").random()
        assert v.det_rng("val", 1).random() != r_plain
    finally:
        v.set_default_pepper("")


def test_iban_known_valid():
    assert v.iban_ok("GB82 WEST 1234 5698 7654 32")   # классический пример ISO
    assert v.iban_ok("DE89 3704 0044 0532 0130 00")
    assert v.iban_ok("FR1420041010050500013M02606")   # BBAN с буквой, без пробелов
    assert not v.iban_ok("GB82 WEST 1234 5698 7654 31")  # чек-цифра сбита
    assert not v.iban_ok("toolongvalue123")            # не формат


def test_iban_check_digits_generate_valid():
    country, bban = "DE", "370400440532013000"
    full = country + v.iban_check_digits(country, bban) + bban
    assert v.iban_ok(full)
