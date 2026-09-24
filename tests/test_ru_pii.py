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


def test_passport_variations_faked_and_restored():
    anon = Anonymizer()
    text1 = "паспорт 4509-123456"
    cleaned1 = anon.sanitize_string(text1)
    assert "4509-123456" not in cleaned1
    assert re.search(r"\d{4}-\d{6}", cleaned1)
    assert anon.de_anonymize(cleaned1) == text1

    text2 = "серия 4509 № 123456"
    cleaned2 = anon.sanitize_string(text2)
    assert "4509 № 123456" not in cleaned2
    assert re.search(r"\d{4} № \d{6}", cleaned2)
    assert anon.de_anonymize(cleaned2) == text2

    # слитный номер с контекстом слова «паспорт»
    text3 = "мой паспорт 4509123456 выдан кем-то"
    cleaned3 = anon.sanitize_string(text3)
    assert "4509123456" not in cleaned3
    assert anon.de_anonymize(cleaned3) == text3

    # без контекста таймстемп не считается паспортом
    text4 = "unixtime 1758000000"
    assert anon.sanitize_string(text4) == text4


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


def test_iban_not_swallowed_by_uppercase_tail():
    # регресс: жадные группы забирали ЗАГЛАВНЫЕ слова после IBAN, чек-сумма
    # не сходилась и валидный IBAN оставался нераспознанным
    anon = Anonymizer()
    text = "реквизиты GB82 WEST 1234 5698 7654 32 AND MORE DATA смотрите"
    cleaned = anon.sanitize_string(text)
    assert anon.stats["ibans"] == 1
    assert "GB82 WEST 1234 5698 7654 32" not in cleaned
    assert "AND MORE DATA" in cleaned
    assert anon.de_anonymize(cleaned) == text


def test_iban_max_length_34_masked():
    # BBAN длиннее 26 символов отвергался IBAN_RE — 34-символьный (максимум
    # ISO 13616) IBAN не маскировался вообще
    from compass_llm_filter.core.validators import iban_check_digits
    bban = "1" * 30
    full = "ZZ" + iban_check_digits("ZZ", bban) + bban
    assert len(full) == 34
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"счёт {full} подтверждён")
    assert full not in cleaned
    assert anon.stats["ibans"] == 1
    assert anon.de_anonymize(cleaned) == f"счёт {full} подтверждён"


def test_phone_fake_with_ogrn_checksum_not_remasked():
    # регресс: телефонная фаза подставляет фейк ДО фазы ru_pii; если цифры
    # фейка случайно проходят контрольную сумму ОГРН (~1/11), ru_pii маскирует
    # фейк повторно — обратная подстановка возвращает промежуточный фейк
    anon = Anonymizer()
    text = "перезвоните 7000000000009"
    cleaned = anon.sanitize_string(text)
    assert anon.stats["phones"] == 1
    assert anon.stats["ogrns"] == 0
    assert anon.de_anonymize(cleaned) == text


def test_phone_fake_with_snils_checksum_not_remasked():
    # то же для СНИЛС (~1/100): 11-значный фейк телефона со сошедшейся суммой
    anon = Anonymizer()
    text = "мой номер 70000000075"
    cleaned = anon.sanitize_string(text)
    assert anon.stats["phones"] == 1
    assert anon.stats["snils"] == 0
    assert anon.de_anonymize(cleaned) == text


def test_spaced_phone_fake_tail_not_remasked_as_snils():
    # разделённый пробелами фейк: RE_SNILS матчит его хвост 3-3-3-2 («102 997
    # 048 65» без «+4 ») — равенство с фейком недостаточно, проверять надо
    # и вхождение кандидата в уже вставленный фейк
    anon = Anonymizer()
    text = "тел +7 000 000 001 50"
    cleaned = anon.sanitize_string(text)
    assert anon.stats["phones"] == 1
    assert anon.stats["snils"] == 0
    assert anon.de_anonymize(cleaned) == text


def test_real_identifiers_still_masked_alongside_phone_fakes():
    # фикс «не маскировать фейки повторно» не должен задеть настоящие
    # СНИЛС/ИНН/ОГРН в том же тексте
    anon = Anonymizer()
    text = ("тел 7000000000009, СНИЛС 123-456-789-64, ИНН 7707083893, "
            "ОГРН 1027700132195")
    cleaned = anon.sanitize_string(text)
    assert anon.stats["snils"] == 1
    assert anon.stats["inns"] == 1
    assert anon.stats["ogrns"] == 1
    assert anon.stats["phones"] == 1
    for real in ("123-456-789-64", "7707083893", "1027700132195", "7000000000009"):
        assert real not in cleaned
    assert anon.de_anonymize(cleaned) == text


def test_card_15_and_19_digits_masked():
    # регресс: кандидат карты был жёстко 16-значным (4 группы по 4) —
    # 15-значный Amex и 19-значные карты с валидным Луном утекали
    for text, card in [
        ("карта 378282246310005", "378282246310005"),          # Amex, 15
        ("карта 4444444444444444442", "4444444444444444442"),  # 19 цифр
    ]:
        anon = Anonymizer()
        cleaned = anon.sanitize_string(text)
        assert card not in cleaned
        assert anon.stats["cards"] == 1
        fake_digits_val = _digits(re.search(r"\d{12,19}", cleaned).group(0))
        assert luhn_ok(fake_digits_val) and len(fake_digits_val) == len(card)
        assert anon.de_anonymize(cleaned) == text


def test_card_double_space_groups_masked():
    # группы, разведённые двойными пробелами, тоже карта
    text = "карта 4111  1111  1111  1111"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(text)
    assert "4111  1111" not in cleaned
    assert anon.stats["cards"] == 1
    assert anon.de_anonymize(cleaned) == text


def test_card_long_numbers_with_bad_luhn_untouched():
    # номера заказов 12+ цифр без валидного Луна картой не являются
    text = "заказы 1234567890123456789 и 1234567890123456"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(text)
    assert "1234567890123456789" in cleaned
    assert "1234567890123456" in cleaned
    assert anon.stats["cards"] == 0
    assert anon.de_anonymize(cleaned) == text


def test_phone_fake_with_valid_luhn_not_card_masked():
    # композиция с защитой фейков: фейк телефона 4403351104825 сам проходит
    # Луна (13 цифр) — расширенная карта-фаза обязана его пропустить
    text = "тел 7000000001009"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(text)
    assert anon.stats["phones"] == 1
    assert anon.stats["cards"] == 0
    assert anon.de_anonymize(cleaned) == text


def test_fake_number_retries_on_forced_collision(monkeypatch):
    # фейк паспорта обязан перегенерироваться, если «случайно» совпал с
    # оригиналом (как это делает fake_digits); совпадение подforced-но
    # подменным ГПСЧ — натуральный подбор строки-близнеца невозможен
    import random

    from compass_llm_filter.core import ru_pii
    from compass_llm_filter.core.validators import det_rng

    digits = "4509123456"
    calls = {"n": 0}

    class ForcedRng(random.Random):
        def __init__(self, forced: str):
            super().__init__()
            self._forced, self._i = forced, 0

        def choice(self, seq):
            ch = self._forced[self._i % len(self._forced)]
            self._i += 1
            return ch

    real_rng = det_rng

    def fake_det_rng(*parts, **kw):
        calls["n"] += 1
        if len(parts) == 3 and parts[:2] == ("passport", digits) and parts[2] == 0:
            return ForcedRng(digits)  # первая попытка «выдала» оригинал
        return real_rng(*parts, **kw)

    monkeypatch.setattr(ru_pii, "det_rng", fake_det_rng)
    fake = ru_pii.fake_number(digits, digits)
    assert "".join(c for c in fake if c.isdigit()) != digits
    assert calls["n"] >= 2  # был ретрай


def test_fake_snils_valid_when_control_number_is_100():
    # взвешенная сумма с остатком 100 (mod 101): контрольного числа «100» не
    # существует, фейк обязан перегенерироваться с валидной суммой
    from compass_llm_filter.core.validators import snils_check_digits, snils_ok
    from compass_llm_filter.core.ru_pii import fake_snils
    def total(n9: str) -> int:
        return sum(int(d) * (9 - j) for j, d in enumerate(n9))

    number9 = next(str(i).zfill(9) for i in range(1, 10_000_000)
                   if total(str(i).zfill(9)) == 201)
    assert snils_check_digits(number9) == "100"  # невалидное контрольное число

    # ищем оригинал, у которого ПЕРВАЯ попытка генерации попадает на «плохую»
    # сумму — ретрай обязан дать валидный СНИЛС из 11 цифр
    from compass_llm_filter.core.validators import det_rng

    def first_generated_n9(digits_11: str) -> str:
        rng = det_rng("snils", digits_11, 0)
        return "".join(rng.choice("0123456789") for _ in range(9))

    trigger = None
    for i in range(1, 20000):
        d = str(i).zfill(9) + "64"
        t = total(first_generated_n9(d))
        if t > 101 and t % 101 == 100:
            trigger = d
            break
    assert trigger is not None
    fake = fake_snils(trigger, trigger)
    fdigits = "".join(c for c in fake if c.isdigit())
    assert len(fdigits) == 11 and snils_ok(fdigits)
