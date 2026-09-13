FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINELAI_DB_PATH=/data/sentinelai.db

RUN apt-get update \
    && apt-get install --no-install-recommends -y dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system sentinelai \
    && useradd --system --gid sentinelai --home-dir /app sentinelai \
    && mkdir -p /app /data \
    && chown sentinelai:sentinelai /app /data

WORKDIR /app
COPY --chown=sentinelai:sentinelai requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt
COPY --chown=sentinelai:sentinelai . .

USER sentinelai
EXPOSE 10000

CMD ["sh", "-c", "exec gunicorn --no-control-socket --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 35 --graceful-timeout 30 --access-logfile - --error-logfile - app:app"]
