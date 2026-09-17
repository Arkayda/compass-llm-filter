FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[proxy]"

# консоль и код едут внутри пакета
ENV COMPASS_HOST=0.0.0.0 COMPASS_PORT=8080
EXPOSE 8080
CMD ["compass-llm-filter"]
