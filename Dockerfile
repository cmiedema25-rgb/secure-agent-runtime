FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system runtime && useradd --system --gid runtime --create-home runtime

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY config ./config
COPY evals ./evals

RUN python -m pip install --no-cache-dir .

RUN mkdir -p /app/var && chown -R runtime:runtime /app/var
USER runtime

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]

CMD ["secure-agent", "serve", "--host", "0.0.0.0", "--port", "8080"]
