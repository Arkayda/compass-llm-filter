#!/usr/bin/env python3
"""Фейковый LLM-провайдер для демо: отвечает эхом последнего сообщения.

Без зависимостей (http.server). В ответ добавляет debug-поле с тем, что
«увидел» провайдер, — чтобы в demo.sh можно было показать обе стороны.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        messages = payload.get("messages", [])
        last_user = next((m.get("content", "") for m in reversed(messages)
                          if m.get("role") == "user"), "")
        print(f"\n[fake-llm] {self.path}: провайдер увидел: {last_user!r}", flush=True)
        response = {
            "choices": [{"message": {"role": "assistant",
                                     "content": f"Принято! Обработаю обращение: {last_user}"}}],
            "model": payload.get("model", "fake"),
            "debug_upstream_saw": last_user,
        }
        body = json.dumps(response, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print("[fake-llm] listening on :9000", flush=True)
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
