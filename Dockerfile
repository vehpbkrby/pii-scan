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
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt requirements-nlp.txt ./

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install -r requirements.txt \
 && if [ "$WITH_NLP" = "1" ]; then \
        /opt/venv/bin/pip install -r requirements-nlp.txt; \
    fi \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} +


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
