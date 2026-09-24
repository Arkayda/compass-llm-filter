"""Тесты ядра обезличивания (compass_llm_filter.core.anonymizer)."""
import pytest

from compass_llm_filter import Anonymizer

TEXT = (
    "Здравствуйте! Пишет Иван Иванов из ООО Ромашка. "
    "Мой телефон +7 912 345-67-89, почта ivan.ivanov@romashka.ru. "
    "Проблема на сервере 203.0.113.7, панель https://panel.romashka.ru/login "
    "не открывается, домен romashka.ru не резолвится. Логи: /var/log/app.log"
)


def test_fake_mode_replaces_everything_sensitive():
    anon = Anonymizer(mode="fake")
    anon.register_entity("ООО Ромашка", kind="org")
    anon.register_entity("Иван Иванов")
    cleaned = anon.sanitize_string(TEXT)

    for real in ("Иванов", "Ромашка", "+7 912 345-67-89", "9123456789",
                 "ivan.ivanov@romashka.ru", "panel.romashka.ru", "romashka.ru"):
        assert real not in cleaned, f"утечка: {real!r} осталось в {cleaned!r}"
    # IP заменён на документный/приватный, файловые пути не тронуты
    assert "203.0.113.7" not in cleaned
    assert "/var/log/app.log" in cleaned
    assert "example.com" in cleaned  # фейковые домены/почты


def test_deterministic_substitutions():
    a1 = Anonymizer(mode="fake")
    a2 = Anonymizer(mode="fake")
    a1.register_entity("ООО Ромашка", kind="org")
    a2.register_entity("ООО Ромашка", kind="org")
    assert a1.sanitize_string(TEXT) == a2.sanitize_string(TEXT)


def test_registered_org_gets_org_style_fake():
    anon = Anonymizer(mode="fake")
    alias = anon.register_entity("ООО Ромашка", kind="org")
    assert alias
    assert alias.startswith(("ООО",)) or " " in alias  # осмысленное название, не ФИО
    assert "Ромашка" not in alias
    cleaned = anon.sanitize_string("Клиент ООО Ромашка прислал запрос")
    assert "Ромашка" not in cleaned
    assert alias in cleaned
    assert anon.leaks_in_text(cleaned) == 0


def test_unregistered_name_in_body_is_left_but_generic_pii_removed():
    # Имя, которого нет в полях тикета, regex-фазами не заменяется (известное
    # ограничение MVP), но телефоны/почты/домены чистятся всегда.
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string("Меня зовут Пётр Свиньин, звоните +7 900 111-22-33")
    assert "Пётр Свиньин" in cleaned
    assert "+7 900 111-22-33" not in cleaned


def test_round_trip_de_anonymize_restores_originals():
    anon = Anonymizer(mode="fake")
    anon.register_entity("ООО Ромашка", kind="org")
    anon.register_entity("Иван Иванов")
    cleaned = anon.sanitize_string(TEXT)
    restored = anon.de_anonymize(cleaned)
    assert "ООО Ромашка" in restored
    assert "Иван Иванов" in restored
    assert "+7 912 345-67-89" in restored
    assert "ivan.ivanov@romashka.ru" in restored
    assert "romashka.ru" in restored


def test_code_boundaries_not_broken():
    anon = Anonymizer(mode="fake")
    anon.register_entity("Compass", kind="org")
    cleaned = anon.sanitize_string(
        "проверьте $compass_service в /opt/compass/backend/docker-compose.yml "
        "и конфиг nginx.conf; версия compass-2.12.1, файл compass_logo.png"
    )
    # латинское имя организации не заменяется внутри путей/переменных/версий
    assert "$compass_service" in cleaned or "$Compass_service" in cleaned
    assert "docker-compose.yml" in cleaned
    assert "nginx.conf" in cleaned
    assert "compass_logo.png" in cleaned


def test_unixtime_and_dates_not_treated_as_phones():
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string("таймстамп 1758000000 от 16.09.2026 12:30")
    assert "1758000000" in cleaned
    assert "16.09.2026" in cleaned


def test_word_boundary_names():
    import re
    anon = Anonymizer(mode="fake")
    anon.register_entity("Иван Иванов")
    cleaned = anon.sanitize_string("Иванов Иван Иванович написал Иван Иванову")
    # Полное имя заменяется только по границам слов: в «Иванову»/«Иванович»
    # оно не трогается (substring-проверка здесь не годится)
    assert re.search(r"\bИван Иванов\b", cleaned) is None
    assert "Иванович" in cleaned


def test_placeholder_mode():
    anon = Anonymizer(mode="placeholders")
    anon.register_entity("ООО Ромашка", kind="org")
    cleaned = anon.sanitize_string(
        "Клиент ООО Ромашка, тел. +7 912 345-67-89 или +7 900 555-44-33, email a@b.ru"
    )
    assert "Ромашка" not in cleaned
    assert "[PHONE]" in cleaned
    assert "[EMAIL]" in cleaned
    # Неоднозначные плейсхолдеры (два телефона -> один и тот же [PHONE])
    # в обратную карту не попадают
    rmap = anon.reverse_map()
    assert rmap.get("[PHONE]") is None


def test_private_ip_stays_private():
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string("хост 10.1.2.3 и внешний 8.8.8.8")
    assert "10." in cleaned.split()[1]  # приватный остался 10.x
    fake_public = cleaned.split()[-1]
    assert fake_public != "8.8.8.8"
    assert fake_public.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_register_entity_ignores_garbage():
    anon = Anonymizer(mode="fake")
    assert anon.register_entity("") is None
    assert anon.register_entity("12345") is None
    assert anon.register_entity("A") is None


TCPDUMP = (
    "listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes\n"
    "11:19:38.810340 ens224 In  IP 5.141.102.236.30039 > 10.208.12.112.8443: UDP, length 32\n"
    "11:19:38.810528 docker_gwbridge Out IP 172.19.0.1.44962 > 172.19.0.40.10000: UDP, length 28\n"
    "11:19:39.526280 ens224 In  IP 5.141.102.236.30039 > 10.208.12.112.8443: UDP, length 32"
)


def test_tcpdump_ip_with_dotted_port_is_anonymized():
    # Регрессия: tcpdump пишет адрес с портом через точку (IP.PORT) — раньше
    # такой IP не матчился и реальный адрес клиента уходил в LLM как есть.
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string(TCPDUMP)
    assert "5.141.102.236" not in cleaned
    assert "10.208.12.112" not in cleaned
    assert "172.19.0.1" not in cleaned
    assert "172.19.0.40" not in cleaned
    # приватные остались приватными, публичный ушёл в документный диапазон
    rmap = anon.reverse_map()
    fake_pub = next(f for f in rmap if rmap[f] == "5.141.102.236")
    assert fake_pub.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    for real_priv in ("10.208.12.112", "172.19.0.1", "172.19.0.40"):
        fake_priv = next(f for f in rmap if rmap[f] == real_priv)
        assert fake_priv.split(".")[0] == real_priv.split(".")[0]
    # порты, таймстемпы и метаданные дампа не тронуты
    assert ".30039" in cleaned and ".8443" in cleaned
    assert "11:19:38.810340" in cleaned
    assert "snapshot length 262144 bytes" in cleaned
    assert anon.leaks_in_text(cleaned) == 0


def test_tcpdump_version_chains_untouched():
    # Длинные точечные цепочки (номера версий) IP-фазой не разбираются.
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string(
        "используйте версию 1.2.3.4.5.6, ядро 6.1.4, время 11:19:38.810340"
    )
    assert "1.2.3.4.5.6" in cleaned
    assert "6.1.4" in cleaned
    assert "11:19:38.810340" in cleaned


def test_round_trip_restores_ip_with_port_and_duplicates():
    # Один и тот же IP в тексте дважды — это не неоднозначность: фейк
    # обязан вернуться в обратную карту и восстанавливаться в черновике.
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string(TCPDUMP)
    rmap = anon.reverse_map()
    fake_pub = next(f for f in rmap if rmap[f] == "5.141.102.236")
    fake_priv = next(f for f in rmap if rmap[f] == "10.208.12.112")
    echo = f"Диагностика: {fake_pub}.30039 шлёт на {fake_priv}.8443, нужен NAT."
    restored = anon.de_anonymize(echo)
    assert "5.141.102.236.30039" in restored
    assert "10.208.12.112.8443" in restored


def test_leaks_in_text_catches_missed_values_not_only_names():
    # Регрессия: самопроверка обязана ловить не только имена, но и
    # телефоны/IP/домены, которые по какой-то причине не заменились.
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string(TCPDUMP)
    assert anon.leaks_in_text(cleaned) == 0
    assert anon.leaks_in_text(cleaned + "\nдропнул пакет от 5.141.102.236") > 0
    # фейк, содержащий реальный фрагмент (example.com внутри фейк-домена),
    # ложной тревоги не даёт
    anon2 = Anonymizer(mode="fake")
    cleaned2 = anon2.sanitize_string("зайдите на support.mycompany.ru, тел. +7 912 345-67-89")
    assert anon2.leaks_in_text(cleaned2) == 0


def test_marker_injection_prevented():
    anon = Anonymizer(mode="fake")
    # Попытка сымитировать внутренний маркер в пользовательском тексте
    evil_text = "Тест секрет api_key=MySecretToken123 \x00s0\x00 \x00s9999\x00 \x000\x00"
    cleaned = anon.sanitize_string(evil_text)
    # Не должно быть падения с IndexError, и чужой секрет не должен подставиться
    assert "MySecretToken123" not in cleaned
    assert "\x00" not in cleaned
    assert anon.de_anonymize(cleaned) == "Тест секрет api_key=MySecretToken123 s0 s9999 0"


def test_ipv6_masked_and_restored():
    anon = Anonymizer(mode="fake")
    text = (
        "Сервер доступен по IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 "
        "и локальному fe80::1ff:fe23:4567:890a, loopback ::1, время 14:25:30"
    )
    cleaned = anon.sanitize_string(text)
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in cleaned
    assert "fe80::1ff:fe23:4567:890a" not in cleaned
    # время не является IPv6 и не должно маскироваться
    assert "14:25:30" in cleaned
    assert anon.stats["ips"] >= 2
    assert anon.leaks_in_text(cleaned) == 0
    restored = anon.de_anonymize(cleaned)
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in restored
    assert "fe80::1ff:fe23:4567:890a" in restored


def test_leak_check_ignores_guarded_path_context():
    # "crontab.cron" в тексте маскируется как домен, но такой же кандидат
    # внутри пути файла ("sh/cron/crontab.cron") доменный детектор
    # сознательно не трогает (lookbehind на "/"). Это не утечка: старая
    # проверка подстрокой считала её ошибкой, и enforce блокировал запрос
    # агента целиком (503 на ровном месте).
    anon = Anonymizer(mode="fake")
    text = (
        "Откройте файл crontab.cron, в нём расписание; полное содержимое: "
        "cat \"${SCRIPT_PATH}/sh/cron/crontab.cron\" | grep hourly"
    )
    cleaned = anon.sanitize_string(text)
    assert "crontab.cron" not in cleaned.split("cat")[0]  # в тексте заменён
    assert "sh/cron/crontab.cron" in cleaned               # в пути сохранён
    assert anon.leaks_in_text(cleaned) == 0


def test_leak_check_catches_real_leftover():
    # настоящая утечка — оригинал в маскируемом контексте — по-прежнему ловится
    anon = Anonymizer(mode="fake")
    cleaned = anon.sanitize_string("напишите на ivan.ivanov@romashka.ru")
    assert "ivan.ivanov@romashka.ru" not in cleaned
    assert anon.leaks_in_text(cleaned + " и продублируйте на ivan.ivanov@romashka.ru") >= 1
    assert anon.leaks_in_text(cleaned) == 0


def test_registered_name_masked_in_any_case():
    # регресс: сравнение имён было регистрозависимым — «ИВАН ИВАНОВ» уходил
    # провайдеру как есть, и leak-check (тоже регистрозависимый) это пропускал
    anon = Anonymizer(mode="fake")
    anon.register_entity("Иван Иванов")
    cleaned = anon.sanitize_string("ИВАН ИВАНОВ кричал, а Иван ИВАНОВ шептал")
    assert "ИВАН ИВАНОВ" not in cleaned
    assert "Иван ИВАНОВ" not in cleaned
    assert anon.leaks_in_text(cleaned) == 0
    assert anon.de_anonymize(cleaned) == "Иван Иванов кричал, а Иван Иванов шептал"


def test_reconcile_keeps_substitutions_in_sync():
    # регресс: при перегенерации фейка (случайное совпадение с реальным именем)
    # новый алиас не попадал в _substitutions — de_anonymize терял имя
    anon = Anonymizer(mode="fake")
    anon.register_entity("Иван Петров")
    anon.register_entity("Пётр Смирнов")
    # симулируем совпадение: фейк второй сущности содержит реальное имя первой
    anon._register("Пётр Смирнов", "Иван Петров Смирнов")
    text = "Иван Петров и Пётр Смирнов в одном тикете"
    masked = anon.sanitize_string(text)  # prepare() -> reconcile() перегенерит фейк
    assert "Иван Петров Смирнов" not in masked
    assert anon.de_anonymize(masked) == text


def test_case_variant_domains_get_distinct_fakes():
    # регресс: хеш фейка считался от lower() — «Corp.Ru» и «corp.ru» давали
    # один фейк, карта отбрасывала неоднозначность, домен не восстанавливался
    anon = Anonymizer(mode="fake")
    text = "зайдите на Corp.Ru и corp.ru"
    cleaned = anon.sanitize_string(text)
    assert cleaned.split()[-1] != cleaned.split()[2]  # фейки различны
    assert anon.de_anonymize(cleaned) == text
