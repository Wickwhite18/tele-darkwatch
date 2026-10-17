FROM python:3.12-slim

# Tor provides the SOCKS5 proxy used by the dark-web collector.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Optional: start tor automatically when the container runs in "daemon" mode.
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/data"]
ENV DW_DB_PATH=/data/darkwatch.db \
    DW_RULES_PATH=/data/rules.json

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["daemon"]
