FROM python:3.12-slim

RUN groupadd -r compass && useradd -r -g compass -d /app -s /sbin/nologin compass

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[proxy]" && chown -R compass:compass /app

USER compass

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/healthz")'

ENV COMPASS_HOST=0.0.0.0 COMPASS_PORT=8080
EXPOSE 8080
CMD ["compass-llm-filter"]
