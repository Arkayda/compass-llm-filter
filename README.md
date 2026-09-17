# compass-llm-filter

Маскирование персональных данных в запросах к LLM и восстановление оригиналов
в ответах. Используется хелпдеском Compass (Inception) как прослойка между
бэкендом и внешним LLM-провайдером.

Все запросы к модели проходят через фильтр: телефоны, e-mail, ссылки и домены,
IPv4, имена и организации, банковские карты, СНИЛС, ИНН, ОГРН/ОГРНИП, паспорта
РФ, IBAN, API-ключи и токены заменяются правдоподобными подстановками. Модель
пишет естественный ответ, в котором подстановки автоматически меняются на
оригиналы перед показом пользователю. Стриминговые ответы (SSE) восстанавливаются
токен-за-токеном, включая фейки, разрезанные границей дельт.

```
приложение ──► compass-llm-filter ──[подстановки]──► LLM-провайдер
     ▲                                            |
     └────[восстановление оригиналов]◄────────────┘
```

Подстановки детерминированные (seed = SHA256 значения): одно и то же значение
всегда заменяется одинаково, состояние между запросами не хранится. Карта
«фейк → оригинал» живёт только в рамках одного запроса. По умолчанию fail-closed:
ошибка маскирования — 503, наружу ничего не уходит.

## Состав

- Библиотека `compass_llm_filter` — ядро на чистом stdlib, без зависимостей.
- Reverse-proxy (extra `[proxy]`) — встаёт между приложением и провайдером,
  в приложении меняется только base URL.
- Веб-консоль `/console` — срабатывания, правила, песочница, аудит. Едет внутри
  pip-пакета, сборки не требует.

Имена и организации не имеют формата и регулярками не находятся — их можно
передавать из приложения: заголовком `X-Compass-Entities` у прокси или методом
`register_entity()` у библиотеки.

## Запуск прокси

Демо без реального провайдера (фильтр + echo-LLM в compose):

```sh
cd examples/quickstart
docker compose up --build   # в другом терминале:
bash demo.sh
```

С реальным провайдером меняется только base URL:

```sh
docker build -t compass-llm-filter -f docker/Dockerfile .
docker run --rm -p 8080:8080 \
  -e COMPASS_UPSTREAM_BASE_URL=https://open.bigmodel.cn/api/paas/v4 \
  compass-llm-filter
```

Пример запроса:

```sh
curl -sS http://localhost:8080/chat/completions \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H 'X-Compass-Entities: ["\u041e\u041e\u041e \u0420\u043e\u043c\u0430\u0448\u043a\u0430"]' \
  -d '{"model":"glm-5.2","messages":[{"role":"user","content":"Мой телефон +7 912 345-67-89, перезвоните"}]}'
```

Провайдер получает подстановку, в ответе клиенту возвращается оригинал.
`X-Compass-Entities` — имена/организации, известные приложению. Кириллица
сырыми UTF-8 байтами работает, но ASCII-JSON (`json.dumps` в Python) надёжнее:
его не портят промежуточные прокси.

## Использование как библиотеки

```python
from compass_llm_filter import Anonymizer

anon = Anonymizer(mode="fake")
anon.register_entity("ООО Ромашка", kind="org")

masked = anon.sanitize_string("Клиент ООО Ромашка, тел. +7 912 345-67-89")
assert anon.leaks_in_text(masked) == 0     # самопроверка на утечки

draft = llm_generate(masked)
real = anon.de_anonymize(draft)            # фейки → оригиналы
```

Режимы: `fake` (реалистичные подстановки, точная обратная замена) и
`placeholders` (`[PHONE]`/`[EMAIL]`).

## Конфигурация прокси

| Переменная | По умолчанию | Описание |
|---|---|---|
| `COMPASS_UPSTREAM_BASE_URL` | — | адрес LLM-провайдера (обязательна) |
| `COMPASS_MODE` | `enforce` | `detect` — shadow-режим: считать и логировать, трафик не трогать |
| `COMPASS_FAIL_MODE` | `closed` | `closed` — ошибка маскирования → 503; `open` — пропустить |
| `COMPASS_ANONYMIZATION_MODE` | `fake` | `fake` \| `placeholders` |
| `COMPASS_HOST` / `COMPASS_PORT` | `0.0.0.0` / `8080` | адрес прокси |
| `COMPASS_METRICS_ENABLED` | `true` | `/metrics` в формате Prometheus |
| `COMPASS_AUDIT_MAX_ENTRIES` | `1000` | кольцевой буфер аудита |
| `COMPASS_MAX_BODY_BYTES` | `10485760` | лимит тела запроса |
| `COMPASS_CUSTOM_RULES_FILE` | — | JSON-файл кастомных правил, грузится при старте |
| `COMPASS_STATE_FILE` | — | JSON-файл состояния: настройки и правила переживают рестарт |
| `COMPASS_AUTH_USER` / `COMPASS_AUTH_PASSWORD` | — | basic-auth консоли и `/v1/*` (задаются парой; пустые — без авторизации) |

## Консоль

`http://localhost:8080/console` — счётчики срабатываний по типам, правила
(встроенные и свои), песочница и журнал аудита. Консоль и управляющий API
(`/v1/*`) закрываются basic-auth через `COMPASS_AUTH_USER`/`COMPASS_AUTH_PASSWORD`
(проксируемый трафик ходит мимо авторизации). Если auth не задан — держите
управляющие эндпоинты внутри сети.

## Разработка

```sh
pip install -e ".[proxy,dev]"
pytest
```

## Лицензия

Apache-2.0.
