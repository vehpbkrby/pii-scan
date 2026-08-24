# syntax=docker/dockerfile:1
#
# Два варианта сборки:
#   docker build -t pii-scan:slim .                          # только regex, ~150 МБ
#   docker build --build-arg WITH_NLP=1 -t pii-scan:full .   # + NER, ~700 МБ
#
# База — python:3.10-slim осознанно: natasha тянет pymorphy2, который
# использует inspect.getargspec, удалённый в Python 3.11. На 3.10 всё работает.

FROM python:3.10-slim AS builder

ARG WITH_NLP=0
# Для контура с TLS-инспектором или внутренним зеркалом PyPI:
#   --build-arg PIP_INDEX_URL=https://nexus.corp/repository/pypi/simple
#   --build-arg PIP_TRUSTED_HOST=nexus.corp
# и корневой сертификат файлом ca-cert.crt рядом с Dockerfile.
ARG PIP_INDEX_URL=""
ARG PIP_TRUSTED_HOST=""
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
# ca-cert* необязателен: шаблон без совпадений допустим, пока в списке
# есть файл, который точно существует
COPY requirements.txt requirements-nlp.txt ca-cert* ./

# pip проверяет сертификаты по связке certifi, а не по системному хранилищу,
# поэтому корпоративный корневой сертификат нужно и добавить в систему,
# и явно указать pip через PIP_CERT.
RUN set -eu; \
    CERT_FILE="$(ls ca-cert* 2>/dev/null | head -1 || true)"; \
    if [ -n "$CERT_FILE" ]; then \
        echo "Корневой сертификат $CERT_FILE добавлен в доверенные"; \
        cp "$CERT_FILE" /usr/local/share/ca-certificates/corporate-ca.crt; \
        update-ca-certificates >/dev/null; \
        export PIP_CERT=/etc/ssl/certs/ca-certificates.crt; \
    fi; \
    [ -n "$PIP_INDEX_URL" ] && export PIP_INDEX_URL || true; \
    [ -n "$PIP_TRUSTED_HOST" ] && export PIP_TRUSTED_HOST || true; \
    python -m venv /opt/venv; \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel; \
    /opt/venv/bin/pip install -r requirements.txt; \
    if [ "$WITH_NLP" = "1" ]; then \
        /opt/venv/bin/pip install -r requirements-nlp.txt; \
    fi; \
    find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} +


FROM python:3.10-slim

LABEL org.opencontainers.image.title="pii-scan" \
      org.opencontainers.image.description="Поиск персональных данных (152-ФЗ) в MySQL и ClickHouse" \
      org.opencontainers.image.licenses="MIT"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PII_OUT=/out

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY pii_scan ./pii_scan

# Непривилегированный пользователь; писать разрешено только в /out
RUN useradd --system --uid 10001 --create-home scanner \
 && mkdir -p /out /config \
 && chown scanner:scanner /out

USER scanner

ENTRYPOINT ["python", "-m", "pii_scan"]
CMD ["--help"]
