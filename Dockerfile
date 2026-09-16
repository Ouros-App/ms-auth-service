FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_PORT=8000

WORKDIR /app

RUN addgroup --system ouros \
    && adduser --system --ingroup ouros --home /app ouros

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=ouros:ouros app ./app

USER ouros
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('APP_PORT', '8000') + '/health', timeout=2)"

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${APP_PORT:-8000}"]
