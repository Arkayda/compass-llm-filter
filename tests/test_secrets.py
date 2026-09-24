"""Тесты каталога секретов (compass_llm_filter.core.secrets)."""
import re

from compass_llm_filter import Anonymizer

OPENAI_KEY = "sk-proj-abcdef1234567890abcdef1234"
GITHUB_KEY = "ghp_" + "a1B2c3D4e5" * 4          # 40 символов
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"    # 16 после AKIA
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"


def test_openai_key_faked():
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"используйте ключ {OPENAI_KEY} для запроса")
    assert OPENAI_KEY not in cleaned
    assert len(re.search(r"\bsk-proj-\S+", cleaned).group(0)) == len(OPENAI_KEY)
    assert anon.de_anonymize(cleaned) == f"используйте ключ {OPENAI_KEY} для запроса"


def test_github_aws_keys_faked():
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"токены: {GITHUB_KEY} и {AWS_KEY}")
    assert GITHUB_KEY not in cleaned and AWS_KEY not in cleaned
    assert anon.stats["secrets"] == 2


def test_bearer_token_label_preserved():
    anon = Anonymizer()
    token = "abcdefghijklmnopqrstuvwxyz123456"
    cleaned = anon.sanitize_string(f"Authorization: Bearer {token}")
    assert token not in cleaned
    assert "Authorization: Bearer " in cleaned
    assert anon.de_anonymize(cleaned) == f"Authorization: Bearer {token}"


def test_kv_secret_label_preserved_value_faked():
    anon = Anonymizer()
    cleaned = anon.sanitize_string("config: api_key=supersecretvalue123")
    assert "api_key=" in cleaned
    assert "supersecretvalue123" not in cleaned
    assert anon.de_anonymize(cleaned) == "config: api_key=supersecretvalue123"
    # connection string: схема/логин/порт остаются, пароль и хост фейкуются
    conn = "db: postgres://admin:secretpass123@db.local:5432/x"
    cleaned2 = anon.sanitize_string(conn)
    assert "postgres://admin:" in cleaned2 and ":5432/x" in cleaned2
    assert "secretpass123" not in cleaned2 and "db.local" not in cleaned2
    assert anon.de_anonymize(cleaned2) == conn


def test_conn_string_not_double_masked():
    """Регресс: фейк-пароль в postgres://user:FAKE@host email-фаза считала
    адресом и маскировала повторно — цепочка подстановок ломала восстановление."""
    line = "строка: postgres://billing:hunter2pass@db.romashka.ru:5432/prod"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(line)
    assert "hunter2pass" not in cleaned and "db.romashka.ru" not in cleaned
    assert anon.stats["emails"] == 0  # повторной маскировки не было
    assert anon.de_anonymize(cleaned) == line


def test_bearer_jwt_masked_once():
    """Регресс: «Bearer <jwt>» раньше маскировали и jwt-, и bearer-правило
    (подстановка поверх подстановки)."""
    header = f"Authorization: Bearer {JWT}"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(header)
    assert JWT not in cleaned
    assert "Authorization: Bearer " in cleaned
    assert anon.stats["secrets"] == 1
    assert anon.de_anonymize(cleaned) == header


def test_jwt_faked():
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"передайте {JWT} в заголовке")
    assert JWT not in cleaned
    assert anon.de_anonymize(cleaned) == f"передайте {JWT} в заголовке"


def test_private_key_header_faked():
    anon = Anonymizer()
    header = "-----BEGIN RSA PRIVATE KEY-----"
    cleaned = anon.sanitize_string(header)
    assert header not in cleaned


def test_full_multiline_private_key_faked_and_restored():
    anon = Anonymizer()
    key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "QyNTUxOQAAACDNX+8p/g2GZQ8dZ2fK9bS51o4u48rZ0Zt1bZ98gqX7awAAAJBq7J00auyd\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    cleaned = anon.sanitize_string(f"конфиг сервера:\n{key}\nпроверьте доступ")
    assert "b3BlbnNzaC1rZXktdjE" not in cleaned
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in cleaned
    assert "-----END OPENSSH PRIVATE KEY-----" not in cleaned
    assert anon.stats["secrets"] >= 1
    assert anon.leaks_in_text(cleaned) == 0
    restored = anon.de_anonymize(cleaned)
    assert key in restored


def test_glm_key_shape_faked():
    # ключ BigModel/GLM: 32 hex-символа, точка, пароль (здесь — синтетический)
    key = "0123456789abcdef0123456789abcdef.FakePassw0rd17"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"GLM_KEY={key}")
    assert key not in cleaned
    assert anon.stats["secrets"] >= 1


def test_secrets_deterministic_and_no_leaks():
    a1, a2 = Anonymizer(), Anonymizer()
    text = f"ключи {OPENAI_KEY} / {GITHUB_KEY}"
    c1, c2 = a1.sanitize_string(text), a2.sanitize_string(text)
    assert c1 == c2
    assert a1.leaks_in_text(c1) == 0


def test_placeholders_mode_secret():
    anon = Anonymizer(mode="placeholders")
    cleaned = anon.sanitize_string(f"ключ {OPENAI_KEY} и {GITHUB_KEY}")
    assert "[SECRET]" in cleaned
    assert anon.reverse_map().get("[SECRET]") is None  # два секрета → неоднозначно


def test_url_with_key_inside_faked_as_link():
    # URL с ключом в query целиком становится фейк-ссылкой (фаза ссылок раньше)
    url = "https://api.example.com/v1/data?key=abc123def456ghi789"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"запрос {url} вернул 200")
    assert "abc123def456ghi789" not in cleaned
    assert "example.com/" in cleaned  # фейковая ссылка


def test_kv_secret_prose_value_not_masked():
    # регресс: kv-правило заменяло прозаические значения — «token:
    # authentication failed for user» терял слово «authentication»
    anon = Anonymizer()
    text = "token: authentication failed for user"
    cleaned = anon.sanitize_string(text)
    assert cleaned == text
    assert anon.stats["secrets"] == 0


def test_kv_secret_values_with_digits_still_masked():
    # у настоящих секретов почти всегда есть цифра или спецсимвол
    anon = Anonymizer()
    text = "config: api_key=supersecretvalue123 и password=hunter2password22"
    cleaned = anon.sanitize_string(text)
    assert "supersecretvalue123" not in cleaned
    assert "hunter2password22" not in cleaned
    assert "api_key=" in cleaned
    assert anon.de_anonymize(cleaned) == text


def test_secret_fakes_keep_prefix_and_separators():
    # регресс: фейки не сохраняли форму — AKIA/AIza теряли префикс, JWT/GLM
    # теряли точки, telegram-ключ двоеточие (вопреки заявлению докстринга)
    google_key = "AIza" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    glm_key = "0123456789abcdef0123456789abcdef.FakePassw0rd17"
    tg_key = "123456789:AAHdy7654321abcdefghij0123456789_"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"ключи {AWS_KEY} {google_key} {glm_key} {tg_key}")
    assert cleaned.count("AKIA") == 1   # префикс AWS сохранён
    assert cleaned.count("AIza") == 1   # префикс Google сохранён
    assert cleaned.count(".") == 1      # точка GLM-ключа на месте
    assert cleaned.count(":") == 1      # двоеточие telegram-ключа на месте
    assert anon.stats["secrets"] == 4
    restored = anon.de_anonymize(cleaned)
    for real in (AWS_KEY, google_key, glm_key, tg_key):
        assert real in restored


def test_private_key_header_fake_keeps_shape():
    header = "-----BEGIN RSA PRIVATE KEY-----"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(header)
    assert header not in cleaned
    assert "PRIVATE" not in cleaned
    # каркас блока: ведущие/замыкающие дефисы сохранены
    assert cleaned.startswith("-----") and cleaned.endswith("-----")
    assert anon.de_anonymize(cleaned) == header


def test_slack_xoxe_token_masked():
    token = "xoxe-123456789012-1234567890123-abcdefABCDEF1234567890ab"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"слак-токен {token}")
    assert token not in cleaned
    assert anon.stats["secrets"] == 1
    assert anon.de_anonymize(cleaned) == f"слак-токен {token}"


def test_bearer_case_insensitive():
    token = "abcdefghijklmnopqrstuvwxyz123456"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(f"Authorization: BEARER {token}")
    assert token not in cleaned
    assert "BEARER " in cleaned  # метка сохранена
    assert anon.de_anonymize(cleaned) == f"Authorization: BEARER {token}"


def test_kv_label_suffixes_masked():
    # SECRET_KEY= / secret_key= / client_secret= / api_key_id= — хвост
    # «_слово» после метки раньше не матчился из-за \b перед «=»
    for label in ("SECRET_KEY", "secret_key", "client_secret", "api_key_id"):
        value = "supersecretvalue123"
        anon = Anonymizer()
        cleaned = anon.sanitize_string(f"{label}={value}")
        assert value not in cleaned
        assert label in cleaned
        assert anon.de_anonymize(cleaned) == f"{label}={value}"


def test_sk_dash_words_without_digits_not_secret():
    # «sk-warehouse-certified-professional» — сертификат, а не ключ OpenAI
    text = "сертификация sk-warehouse-certified-professional пройдена"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(text)
    assert cleaned == text
    assert anon.stats["secrets"] == 0


def test_conn_string_private_host_fakes_keep_class():
    # регресс: _fake_host не знал про 127.0.0.0/8 и 169.254.0.0/16 — loopback
    # и link-local хосты получали публичный фейк, в отличие от bare-IP фазы
    conns = {
        "postgres://u:secretpw1@127.0.0.1:5432/db": r"@127\.\d+\.\d+\.\d+:",
        "metadata://user:pass12345@169.254.169.254/latest": r"@169\.254\.\d+\.\d+",
    }
    for conn, fake_re in conns.items():
        anon = Anonymizer()
        cleaned = anon.sanitize_string(conn)
        assert re.search(fake_re, cleaned), cleaned
        assert anon.de_anonymize(cleaned) == conn


def test_conn_string_scheme_not_quadratic():
    # регресс: жадная схема [a-z][a-z0-9+.-]*:// откатывалась посимвольно с
    # каждой буквы длинного «a.a.a...» — O(n^2), 16k повторов давали секунды
    import time
    anon = Anonymizer()
    text = "t " + "a." * 20000 + " конец"
    t0 = time.perf_counter()
    anon.sanitize_string(text)
    dt = time.perf_counter() - t0
    assert dt < 1.0, f"маскировка строки подключения нелинейна: {dt:.2f}s"


def test_conn_string_bare_label_host_masked():
    # регресс: хост из одной метки (localhost/redis) не попадал в
    # alternation хоста — строка подключения уходила в LLM целиком, не
    # маскируясь (и leak-check молчал)
    conns = [
        "mysql://root:Sup3rS3cretPw@localhost:3306/db",
        "redis://cache:MyRedisPassw0rd@redis:6379/0",
    ]
    for conn in conns:
        anon = Anonymizer()
        cleaned = anon.sanitize_string(conn)
        assert "Sup3rS3cretPw" not in cleaned
        assert "MyRedisPassw0rd" not in cleaned
        assert "@localhost" not in cleaned and "@redis:" not in cleaned
        assert anon.leaks_in_text(cleaned) == 0
        assert anon.de_anonymize(cleaned) == conn


def test_conn_string_marker_password_not_corrupted():
    # регресс: пароль, уже заменённый sk--правилом на внутренний маркер \x00,
    # целиком съедался классом пароля conn_string — в карту подстановок
    # попадал сам маркер, и обратная подстановка возвращала мусор
    conn = "postgres://u:sk-abcdef1234567890gh@db.corp.ru:5432/x"
    anon = Anonymizer()
    cleaned = anon.sanitize_string(conn)
    assert "sk-abcdef1234567890gh" not in cleaned
    assert "db.corp.ru" not in cleaned
    assert anon.stats["secrets"] == 2  # sk-ключ + хост
    assert anon.de_anonymize(cleaned) == conn


def test_conn_string_with_ip_and_ipv6():
    anon = Anonymizer()
    # Строка подключения с IPv4 адресом
    conn_ip = "db: postgres://admin:SuperSecretPass123@10.0.1.25:5432/production"
    cleaned_ip = anon.sanitize_string(conn_ip)
    assert "SuperSecretPass123" not in cleaned_ip
    assert "10.0.1.25" not in cleaned_ip
    assert "postgres://admin:" in cleaned_ip and ":5432/production" in cleaned_ip
    assert anon.leaks_in_text(cleaned_ip) == 0
    assert anon.de_anonymize(cleaned_ip) == conn_ip

    # Строка подключения с IPv6 адресом
    conn_ipv6 = "redis://user:MyRedisSecret@[2001:db8::1]:6379/0"
    cleaned_ipv6 = anon.sanitize_string(conn_ipv6)
    assert "MyRedisSecret" not in cleaned_ipv6
    assert "2001:db8::1" not in cleaned_ipv6
    assert anon.de_anonymize(cleaned_ipv6) == conn_ipv6
