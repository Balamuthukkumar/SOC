FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt asyncpg

COPY alembic.ini .
COPY migrations migrations
COPY app app
# Build the UI first (`cd frontend && npm run build`) so this includes it:
COPY frontend/dist frontend/dist

RUN useradd --system --no-create-home app && chown -R app /srv
USER app

ENV ENVIRONMENT=production PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health/live')"
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers 1"]
