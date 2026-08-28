# --- builder: compile deps that need build-essential, then discard it ---
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- runtime: slim image, no compiler toolchain ---
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /install /usr/local
COPY . .

RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

ENV PORT=8080 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/tmp/hf_home
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",8080)}/healthz', timeout=3)" || exit 1

# Single worker: the RAG pipelines hold in-memory BM25 indexes + an embedding
# model per worker process, so more workers multiply memory linearly for no
# throughput benefit under typical coursework/demo load. Bump --threads to
# add concurrency instead. Shell form so $PORT (injected by most PaaS
# platforms, e.g. Cloud Run) is honored instead of the ENV default above.
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 300 app:app
