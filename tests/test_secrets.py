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
    # пароль в connection string: схема/логин/порт остаются, пароль и хост
    # фейкуются (хост — доменной фазой, это корректно)
    cleaned2 = anon.sanitize_string("db: postgres://admin:secretpass123@db.local:5432/x")
    assert "postgres://admin:" in cleaned2 and ":5432/x" in cleaned2
    assert "secretpass123" not in cleaned2 and "db.local" not in cleaned2


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
