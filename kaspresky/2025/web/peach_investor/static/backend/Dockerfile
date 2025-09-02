FROM python:3.11-slim

WORKDIR /app

ENV FORKED_BY_MULTIPROCESSING=1

RUN apt-get update && apt-get install -y \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -r app && useradd -r -g app -d /home/appuser -m appuser && chown -R appuser:app /app

COPY app/ .

COPY start.sh .
RUN chmod +x /app/start.sh

COPY flag /flag_redacted_random_path

USER appuser

CMD mkdir -p /app/data /app/uploads /app/results

CMD ["sh", "./start.sh"]
