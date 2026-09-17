"""Тесты фаз российских идентификаторов (compass_llm_filter.core.ru_pii)."""
import re

from compass_llm_filter import Anonymizer
from compass_llm_filter.core.validators import iban_ok, inn_ok, luhn_ok, ogrn_ok, snils_ok


def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def test_card_luhn_valid_faked_with_valid_fake():
    anon = Anonymizer()
    cleaned = anon.sanitize_string("оплатите картой 4111 1111 1111 1111 пожалуйста")
    assert "4111 1111 1111 1111" not in cleaned
    fake = re.search(r"\d{4} \d{4} \d{4} \d{4}", cleaned).group(0)
    assert luhn_ok(_digits(fake))          # фейк тоже проходит Луна
    assert anon.stats["cards"] == 1
    assert anon.de_anonymize(cleaned) == "оплатите картой 4111 1111 1111 1111 пожалуйста"


def test_card_separators_preserved():
    anon = Anonymizer()
    dash = anon.sanitize_string("карта 4111-1111-1111-1111")
    solid = anon.sanitize_string("карта 4111111111111111")
    assert re.search(r"\d{4}-\d{4}-\d{4}-\d{4}", dash)
    assert re.search(r"(?<![\d.])\d{16}(?![\d.])", solid)


def test_card_invalid_luhn_untouched_by_card_phase():
    # невалидная по Луну карта — не карта (и не телефон: 16 цифр) — остаётся
    anon = Anonymizer()
    cleaned = anon.sanitize_string("номер 4111 1111 1111 1112")
    assert "4111 1111 1111 1112" in cleaned
    assert anon.stats["cards"] == 0


def test_snils_faked_and_deterministic():
    a1, a2 = Anonymizer(), Anonymizer()
    text = "мой СНИЛС 123-456-789-64"
    c1, c2 = a1.sanitize_string(text), a2.sanitize_string(text)
    assert "123-456-789-64" not in c1
    assert snils_ok(_digits(re.search(r"\d{3}-\d{3}-\d{3}-\d{2}", c1).group(0)))
    assert c1 == c2  # детерминизм
    assert a1.de_anonymize(c1) == text


def test_snils_invalid_checksum_falls_to_phone_phase():
    # 123-456-789-06: сумма не сходится, но по форме — телефон (11 цифр с
    # разделителями) — обезличивается телефонной фазой, реальное значение не утекает
    anon = Anonymizer()
    cleaned = anon.sanitize_string("СНИЛС вроде 123-456-789-06")
    assert "123-456-789-06" not in cleaned
    assert anon.stats["snils"] == 0 and anon.stats["phones"] == 1


def test_inn10_faked_and_roundtrip():
    anon = Anonymizer()
    text = "ИНН организации 7707083893, выставите счёт"
    cleaned = anon.sanitize_string(text)
    assert "7707083893" not in cleaned
    fake = re.search(r"(?<![\d.])\d{10}(?![\d.])", cleaned).group(0)
    assert inn_ok(fake)
    assert anon.de_anonymize(cleaned) == text


def test_inn12_and_ogrnip_faked():
    anon = Anonymizer()
    text = "ИНН ИП 500100732259, ОГРНИП 304500116000157"
    cleaned = anon.sanitize_string(text)
    assert "500100732259" not in cleaned and "304500116000157" not in cleaned
    assert anon.de_anonymize(cleaned) == text


def test_ogrn_faked_but_contract_number_still_phone_faked():
    # 13-значный номер договора без валидной ОГРН-суммы: ru_pii не трогает,
    # телефонная фаза уже заменила — реальное значение отсутствует
    anon = Anonymizer()
    cleaned = anon.sanitize_string("ОГРН 1027700132195, договор 8892834271636")
    assert "1027700132195" not in cleaned
    assert "8892834271636" not in cleaned
    assert anon.stats["ogrns"] == 1


def test_unixtime_and_dates_stay():
    anon = Anonymizer()
    cleaned = anon.sanitize_string("таймстамп 1758000000 от 16.09.2026 12:30")
    assert "1758000000" in cleaned
    assert "16.09.2026" in cleaned


def test_passport_faked():
    anon = Anonymizer()
    text = "паспорт 4509 123456 выдан в 2020"
    cleaned = anon.sanitize_string(text)
    assert "4509 123456" not in cleaned
    assert re.search(r"\d{4} \d{6}", cleaned)
    assert anon.de_anonymize(cleaned) == text


def test_tcpdump_regress_still_clean():
    # старый регресс не должен сломаться новыми фазами (длинные цифровые цепочки)
    anon = Anonymizer()
    tcpdump = "11:19:38.810340 ens224 In IP 5.141.102.236.30039 > 10.208.12.112.8443: UDP, length 262144"
    cleaned = anon.sanitize_string(tcpdump)
    assert "5.141.102.236" not in cleaned and "10.208.12.112" not in cleaned
    assert "11:19:38.810340" in cleaned and "262144" in cleaned
    assert anon.leaks_in_text(cleaned) == 0


def test_placeholders_mode_tokens():
    anon = Anonymizer(mode="placeholders")
    cleaned = anon.sanitize_string(
        "карта 4111 1111 1111 1111, СНИЛС 12345678964, паспорт 4509 123456"
    )
    assert "[CARD]" in cleaned and "[SNILS]" in cleaned and "[PASSPORT]" in cleaned
    assert anon.reverse_map().get("[CARD]") == "4111 1111 1111 1111"
    # два разных ИНН дают одинаковый плейсхолдер — неоднозначный, не восстанавливается
    cleaned2 = anon.sanitize_string("ИНН 7707083893 и ИНН 500100732259")
    assert cleaned2.count("[INN]") == 2
    assert anon.reverse_map().get("[INN]") is None


def test_combined_text_no_leaks_and_full_roundtrip():
    anon = Anonymizer()
    anon.register_entity("ООО Ромашка", kind="org")
    text = ("Клиент ООО Ромашка: карта 4111 1111 1111 1111, СНИЛС 12345678964, "
            "ИНН 7707083893, тел +7 912 345-67-89, ip 203.0.113.7")
    cleaned = anon.sanitize_string(text)
    assert anon.leaks_in_text(cleaned) == 0
    restored = anon.de_anonymize(cleaned)
    assert "ООО Ромашка" in restored and "4111 1111 1111 1111" in restored
    assert "+7 912 345-67-89" in restored and "7707083893" in restored


def test_iban_masked_with_valid_fake_and_roundtrip():
    anon = Anonymizer()
    original = "GB82 WEST 1234 5698 7654 32"
    cleaned = anon.sanitize_string(f"реквизиты для оплаты: {original}")
    assert original not in cleaned
    assert anon.stats["ibans"] == 1
    fake = cleaned.split(":")[1].strip()
    assert iban_ok(fake.replace(" ", ""))          # фейк — валидный IBAN
    assert fake[:2] == "GB82"[:2]                  # страна сохранена
    assert len(fake.replace(" ", "")) == len(original.replace(" ", ""))
    assert anon.de_anonymize(cleaned) == f"реквизиты для оплаты: {original}"


def test_iban_invalid_checksum_not_iban():
    # чек не прошёл — IBAN не опознан; цифровой хвост телефонная фаза маскирует
    # как обычный цифровой блок (консервативно), префикс остаётся как есть
    anon = Anonymizer()
    cleaned = anon.sanitize_string("счёт GB82 WEST 1234 5698 7654 31 неверный")
    assert "GB82 WEST" in cleaned
    assert "1234 5698 7654 31" not in cleaned
    assert anon.stats["ibans"] == 0
