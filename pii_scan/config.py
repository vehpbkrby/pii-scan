# -*- coding: utf-8 -*-
"""Загрузка и валидация конфигурации.

Пароли в файл не пишутся: строки вида ${MYSQL_PWD} подставляются из окружения
(в docker compose — из .env). Отсутствующая переменная — ошибка запуска, а не
пустой пароль.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SUPPORTED_TYPES = ("mysql", "clickhouse")

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

DEFAULT_EXCLUDE_DB = {
    "mysql": ["mysql", "information_schema", "performance_schema", "sys"],
    "clickhouse": ["system", "INFORMATION_SCHEMA", "information_schema"],
}

DEFAULT_SKIP_ENGINES = ["Distributed", "Merge", "Null", "View", "MaterializedView"]

DEFAULT_PORT = {"mysql": 3306, "clickhouse": 8123}


class ConfigError(Exception):
    pass


def _expand(value: Any) -> Any:
    """Рекурсивная подстановка ${VAR} и ${VAR:-default}."""
    if isinstance(value, str):
        def sub(m: "re.Match") -> str:
            name, default = m.group(1), m.group(2)
            env = os.environ.get(name)
            if env is not None:
                return env
            if default is not None:
                return default
            raise ConfigError(
                f"переменная окружения {name} не задана "
                f"(конфиг ссылается на ${{{name}}})"
            )
        return _ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


@dataclass
class ScanOptions:
    sample_limit: int = 500          # строк на таблицу
    max_value_len: int = 512         # обрезка значений на стороне БД
    query_timeout: int = 15          # секунд на запрос
    max_columns_per_query: int = 60  # колонок в одной выборке
    max_threads: int = 2             # ограничение нагрузки (ClickHouse)
    scan_json: bool = True
    max_json_paths: int = 200        # виртуальных колонок на одну JSON-колонку
    ner: bool = True
    ner_values_per_column: int = 50   # бюджет NER: инференс дорогой
    examples_per_hit: int = 3
    allow_rw: bool = False           # разрешить учётку с правами на запись
    dry_run: bool = False            # только схема, ни одного чтения данных
    show_values: bool = False        # не маскировать примеры (осторожно!)


@dataclass
class SourceConfig:
    name: str
    type: str
    host: str
    port: int
    user: str
    password: str = ""
    secure: bool = False              # TLS: HTTPS для ClickHouse, SSL для MySQL
    ssl_ca: str = ""                  # путь к корневому сертификату внутри контейнера
    ssl_verify: bool = True           # проверять сертификат сервера
    databases: List[str] = field(default_factory=list)        # пусто = все
    exclude_databases: List[str] = field(default_factory=list)
    include_tables: List[str] = field(default_factory=list)   # regex
    exclude_tables: List[str] = field(default_factory=list)   # regex
    skip_views: bool = True
    skip_engines: List[str] = field(default_factory=list)     # ClickHouse

    def __post_init__(self) -> None:
        self.exclude_databases = list(
            dict.fromkeys(DEFAULT_EXCLUDE_DB.get(self.type, []) + self.exclude_databases)
        )
        if self.type == "clickhouse" and not self.skip_engines:
            self.skip_engines = list(DEFAULT_SKIP_ENGINES)

    def table_allowed(self, database: str, table: str) -> bool:
        full = f"{database}.{table}"
        if any(re.search(p, full) or re.search(p, table) for p in self.exclude_tables):
            return False
        if self.include_tables:
            return any(
                re.search(p, full) or re.search(p, table) for p in self.include_tables
            )
        return True

    def database_allowed(self, database: str) -> bool:
        if database in self.exclude_databases:
            return False
        return not self.databases or database in self.databases


@dataclass
class AppConfig:
    scan: ScanOptions
    sources: List[SourceConfig]


def _load_raw(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yml", ".yaml")):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise ConfigError("для YAML-конфига нужен PyYAML") from exc
        data = yaml.safe_load(text)
    else:
        import json
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ConfigError("конфиг должен быть объектом верхнего уровня")
    return data


def load_config(path: str) -> AppConfig:
    raw = _expand(_load_raw(path))

    scan_raw = raw.get("scan") or {}
    known = ScanOptions().__dict__.keys()
    unknown = set(scan_raw) - set(known)
    if unknown:
        raise ConfigError(f"неизвестные параметры в scan: {', '.join(sorted(unknown))}")
    scan = ScanOptions(**scan_raw)

    sources_raw = raw.get("sources")
    if not sources_raw:
        raise ConfigError("не задан ни один источник (секция sources)")

    sources: List[SourceConfig] = []
    for i, item in enumerate(sources_raw, 1):
        if not isinstance(item, dict):
            raise ConfigError(f"источник #{i}: ожидался объект")
        stype = str(item.get("type", "")).lower()
        if stype not in SUPPORTED_TYPES:
            raise ConfigError(
                f"источник #{i}: тип '{stype}' не поддерживается "
                f"(доступно: {', '.join(SUPPORTED_TYPES)})"
            )
        for required in ("host", "user"):
            if not item.get(required):
                raise ConfigError(f"источник #{i}: не задан обязательный параметр "
                                  f"'{required}'")
        item = dict(item)
        item["type"] = stype
        item.setdefault("name", f"{stype}-{i}")
        item.setdefault("port", DEFAULT_PORT[stype])
        item["port"] = int(item["port"])
        allowed = SourceConfig.__dataclass_fields__.keys()
        unknown = set(item) - set(allowed)
        if unknown:
            raise ConfigError(
                f"источник '{item['name']}': неизвестные параметры: "
                f"{', '.join(sorted(unknown))}"
            )
        sources.append(SourceConfig(**item))

    names = [s.name for s in sources]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ConfigError(f"повторяющиеся имена источников: {', '.join(sorted(dupes))}")

    return AppConfig(scan=scan, sources=sources)


def find_default_config(candidates: Optional[List[str]] = None) -> Optional[str]:
    for path in candidates or ["/config/config.yml", "config.yml", "config.yaml"]:
        if os.path.isfile(path):
            return path
    return None
