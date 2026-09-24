# Project Rules: Compass LLM Filter

> High-throughput privacy and security reverse-proxy and library for masking/unmasking PII and secrets in LLM interactions.

---

## 1. Privacy & Zero-Leak Invariant (CRITICAL)

1. **No PII in Logs or Traces**:
   - Raw personal data (names, phones, emails, passport/SNILS/INN numbers, API keys) must NEVER be output to logs, console, or unhandled exception tracebacks.
   - Only masked tokens (e.g. `{{EMAIL_1}}`, `{{PHONE_1}}`) and anonymization metadata are permitted in debug logs.
2. **Deterministic & Safe Reversible Mapping**:
   - The substitution mapping (original <-> token) must be strictly isolated per session/request.
   - De-anonymization must never replace tokens outside of the session's active dictionary.

---

## 2. Core Library Invariant (Zero External Dependencies)

1. **Strict Core Independence**:
   - Code inside `src/compass_llm_filter/core/` must rely **exclusively on the Python standard library** (e.g., `re`, `dataclasses`, `typing`, `json`, `hashlib`).
   - Do NOT import `fastapi`, `httpx`, `pydantic`, or any third-party package inside `core/`.
2. **Optional Proxy Scope**:
   - Networking, HTTP reverse-proxying, rate limiting, and web UI reside in `src/compass_llm_filter/proxy/` and depend only on `[project.optional-dependencies] proxy`.

---

## 3. Security & Regex Performance (ReDoS Prevention)

1. **Regular Expression Safety**:
   - All regex patterns in `ru_pii.py`, `secrets.py`, and `injection.py` must avoid catastrophic backtracking (ReDoS).
   - Forbidden: nested indefinite quantifiers like `(a+)+` or overlapping wildcard groups `(.*a.*b)`.
   - Pre-compile patterns with `re.compile()` at module load time.
2. **SSRF Prevention in Proxy**:
   - When forwarding requests to upstream LLM APIs, target hosts must be strictly validated against configured allowlists. Reject internal IP ranges (127.0.0.1, 169.254.169.254, 10.0.0.0/8) unless explicitly permitted for local mock/dev testing.

---

## 4. Streaming Chunk Boundaries (SSE / LLM Streaming)

* LLM stream responses arrive in token chunks. Masked tokens may be cut across chunk boundaries (e.g. chunk 1 has `{{PHONE_`, chunk 2 has `1}}`).
* Streaming de-anonymization buffers must handle partial tokens without corrupting output or introducing significant TTFT (Time To First Token) latency.

---

## 5. Testing & Verification

* Run test suite: `pytest` (async tests with `pytest-asyncio`).
* Any new PII detector must include unit tests with positive and negative samples, as well as edge cases (trailing punctuation, Cyrillic homoglyphs, whitespace variations).
