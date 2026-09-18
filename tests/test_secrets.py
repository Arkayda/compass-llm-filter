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
