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

SUPPORTED_TYPES = ("mysql", "postgres", "clickhouse")
SAMPLE_STRATEGIES = ("head", "tail", "head_tail")

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

DEFAULT_EXCLUDE_DB = {
    "mysql": ["mysql", "information_schema", "performance_schema", "sys"],
    "postgres": ["template0", "template1"],
    "clickhouse": ["system", "INFORMATION_SCHEMA", "information_schema"],
}

DEFAULT_SKIP_ENGINES = ["Distributed", "Merge", "Null", "View", "MaterializedView"]

DEFAULT_PORT = {"mysql": 3306, "postgres": 5432, "clickhouse": 8123}


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
class ThrottleOptions:
    """Ограничение нагрузки. По умолчанию не ограничивает ничего."""
    pause_ms: int = 0                 # пауза между запросами
    max_queries_per_minute: int = 0   # 0 = без ограничения
    max_duration_min: int = 0         # общий бюджет времени прогона


@dataclass
class ScanOptions:
    sample_limit: int = 500          # строк на таблицу
    # head      — первые строки (самые старые), один запрос;
    # tail      — последние строки (самые свежие);
    # head_tail — пополам с обоих концов: ПДн часто появляются в новых
    #             записях, и чтение только «головы» их не видит.
    sample_strategy: str = "head_tail"
    max_value_len: int = 512         # обрезка значений на стороне БД
    query_timeout: int = 15          # секунд на запрос
    max_columns_per_query: int = 60  # колонок в одной выборке
    max_threads: int = 2             # ограничение нагрузки (ClickHouse)
    scan_json: bool = True
    max_json_paths: int = 200        # виртуальных колонок на одну JSON-колонку
    max_bytes_per_table: int = 2_000_000  # потолок трафика на таблицу
    group_similar_tables: bool = True     # шардированные таблицы — по образцу
    group_min_size: int = 4               # с какого размера группы включается
    group_samples: int = 2                # сколько представителей обследовать
    ner: bool = True
    ner_values_per_column: int = 50   # бюджет NER: инференс дорогой
    progress: str = "auto"           # индикатор: auto | on | off
    full_inventory: bool = False     # в отчёт все поля, включая чистые
    # Какие категории ПДн искать. Пусто = все. Принимаются группы
    # (фио, контакты, документы, финансы, рождение, спецкатегории,
    # родственники) и отдельные коды детекторов.
    detectors: List[str] = field(default_factory=list)
    # Замаскированные примеры значений. По умолчанию 0 — не показывать:
    # даже маска оставляет длину, формат и первые символы, а отчёт уходит
    # разработчикам и внешним проверяющим. Включается осознанно.
    examples_per_hit: int = 0
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
    settings: Dict[str, Any] = field(default_factory=dict)    # настройки сессии

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
    throttle: ThrottleOptions = field(default_factory=ThrottleOptions)


def _load_raw(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError as exc:
        raise ConfigError(
            f"конфиг не найден: {path}. Проверьте путь; в контейнере файл "
            f"монтируется как /config/config.yml"
        ) from exc
    except OSError as exc:
        raise ConfigError(f"не удалось прочитать конфиг {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(
            f"конфиг {path} не в кодировке UTF-8: {exc}") from exc

    if path.endswith((".yml", ".yaml")):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise ConfigError("для YAML-конфига нужен PyYAML") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"конфиг {path} — некорректный YAML: {exc}") from exc
    else:
        import json
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ConfigError(f"конфиг {path} — некорректный JSON: {exc}") from exc

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
    if scan.progress not in ("auto", "on", "off"):
        raise ConfigError(
            f"progress: '{scan.progress}' — допустимо auto, on, off")
    try:
        from .detectors import resolve_detectors
        resolve_detectors(scan.detectors)
    except ValueError as exc:
        raise ConfigError(f"detectors: {exc}") from exc
    if scan.sample_strategy not in SAMPLE_STRATEGIES:
        raise ConfigError(
            f"sample_strategy: '{scan.sample_strategy}' — допустимо "
            f"{', '.join(SAMPLE_STRATEGIES)}")

    throttle_raw = raw.get("throttle") or {}
    unknown = set(throttle_raw) - set(ThrottleOptions().__dict__)
    if unknown:
        raise ConfigError(
            f"неизвестные параметры в throttle: {', '.join(sorted(unknown))}")
    throttle = ThrottleOptions(**throttle_raw)

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

    return AppConfig(scan=scan, sources=sources, throttle=throttle)


def find_default_config(candidates: Optional[List[str]] = None) -> Optional[str]:
    for path in candidates or ["/config/config.yml", "config.yml", "config.yaml"]:
        if os.path.isfile(path):
            return path
    return None
