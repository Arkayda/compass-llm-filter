#!/usr/bin/env bash
# Демо compass-llm-filter: запрос с PII через прокси к фейковому LLM.
# Показывает, что увидел провайдер (замаскированный текст, из лога fake-llm —
# он вне прокси) и что получил клиент (оригиналы восстановлены).
# Запуск: bash demo.sh [COMPASS_URL]
#
# Без docker (fake_llm.py на 127.0.0.1:9000): запускайте прокси с
# COMPASS_ALLOW_PRIVATE_UPSTREAM=true — иначе SSRF-защита отклонит
# loopback-апстрим. Docker-compose (хост fake-llm) работает без флага.
set -euo pipefail

COMPASS_URL="${1:-http://localhost:8080}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ENTITIES='["ООО Ромашка"]'

PAYLOAD=$(cat <<EOF
{
  "model": "fake-model",
  "messages": [
    {"role": "user", "content": "Клиент ООО Ромашка! Мой телефон +7 912 345-67-89, карта 4111 1111 1111 1111, ИНН 7707083893, напишите на ivan.ivanov@romashka.ru. Ключ для теста: sk-proj-abcdef1234567890abcdef1234"}
  ]
}
EOF
)

echo "═══ 1. Запрос через compass-llm-filter ($COMPASS_URL) ═══"
echo "Отправляем (с PII): компания, телефон, карта, ИНН, e-mail, API-ключ"
RESPONSE=$(curl -sS "$COMPASS_URL/chat/completions" \
  -H 'Content-Type: application/json' \
  -H "X-Compass-Entities: $ENTITIES" \
  -d "$PAYLOAD")

echo
echo "═══ 2. Что увидел LLM-провайдер (замаскировано; лог fake-llm) ═══"
if command -v docker >/dev/null 2>&1 && docker compose -f "$HERE/docker-compose.yml" ps -q fake-llm >/dev/null 2>&1 && [ -n "$(docker compose -f "$HERE/docker-compose.yml" ps -q fake-llm 2>/dev/null)" ]; then
  docker compose -f "$HERE/docker-compose.yml" logs --tail=1 fake-llm 2>/dev/null | grep -o "провайдер увидел: .*" || true
elif [ -f /tmp/fake_llm.log ]; then
  grep "провайдер увидел" /tmp/fake_llm.log | tail -1 | sed 's/.*провайдер увидел: //'
else
  echo "(лог fake-llm недоступен: под docker — docker compose logs fake-llm)"
fi

echo
echo "═══ 3. Что получил клиент (оригиналы восстановлены) ═══"
echo "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["choices"][0]["message"]["content"])'

echo
echo "═══ 4. Метрики (счётчики срабатываний) ═══"
curl -sS "$COMPASS_URL/metrics" | grep -E '^compass_masked_total\{type="(phones|cards|inns|emails|names|secrets)"\}' || true

echo
echo "Консоль: $COMPASS_URL/console — песочница, правила, аудит."
