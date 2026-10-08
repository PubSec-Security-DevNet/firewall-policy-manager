# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM python:3.12.14-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS builder

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY pyproject.toml requirements.lock ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY src ./src
RUN python -m venv "$VIRTUAL_ENV" \
    && pip install --no-cache-dir --upgrade pip==26.2.1 \
    && pip install --no-cache-dir -r requirements.lock \
    && pip install --no-cache-dir --no-deps . \
    && pip uninstall --yes pip setuptools wheel

FROM python:3.12.14-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app/src

ARG APP_GIT_SHA=unknown
ENV APP_GIT_SHA=$APP_GIT_SHA

WORKDIR /app
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends libpq5 \
    && apt-get purge --yes mount \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app app \
    && python -m pip uninstall --yes pip setuptools wheel

COPY --from=builder /opt/venv /opt/venv
COPY alembic.ini ./
COPY alembic ./alembic
COPY src ./src

USER app
CMD ["uvicorn", "firewall_manager.main:app", "--host", "0.0.0.0", "--port", "8000"]
