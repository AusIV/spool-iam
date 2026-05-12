FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_DEBUG=0 \
    DJANGO_DB_NAME=/data/db.sqlite3 \
    PORT=8000 \
    WEB_CONCURRENCY=2

WORKDIR /app

RUN adduser --disabled-password --gecos "" iam \
    && mkdir -p /data \
    && chown iam:iam /data

COPY pyproject.toml README.md ./
COPY manage.py ./
COPY django_iam ./django_iam
COPY django_iam_client ./django_iam_client
COPY iam_service ./iam_service

RUN pip install --no-cache-dir . gunicorn "psycopg[binary]"

USER iam

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn iam_service.wsgi:application --bind 0.0.0.0:${PORT} --workers ${WEB_CONCURRENCY}"]
