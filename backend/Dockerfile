FROM python:3.12.13-slim-trixie@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080

WORKDIR /app

COPY requirements.lock ./
RUN pip install --root-user-action=ignore --require-hashes -r requirements.lock

COPY main.py app.py api_models.py app_config.py app_stores.py ./
COPY routers ./routers
COPY services ./services
COPY data ./data
COPY eval ./eval

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
