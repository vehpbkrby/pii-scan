# -*- coding: utf-8 -*-
"""Протокол источника данных.

Ядро сканера не знает ни одного диалекта SQL: всё, что специфично для СУБД,
живёт в адаптере. Добавить PostgreSQL или Oracle = добавить один файл.
"""
from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, NamedTuple, Optional, Sequence

from ..config import ScanOptions, SourceConfig

log = logging.getLogger(__name__)

# Признаки «кракозябр»: кириллица в UTF-8, прочитанная как cp1252/latin-1.
_MOJIBAKE_MARKERS = ("Ð", "Ñ", "Ã", "Â")
_CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")


def repair_mojibake(text: str) -> Optional[str]:
    """Восстанавливает строку с двойной кодировкой, иначе возвращает None.

    В legacy-базах кириллица сплошь и рядом записана через соединение с
    неверной кодировкой: 'Голубев' превращается в 'Ð“Ð¾Ð»ÑƒÐ±ÐµÐ²'. Без
    восстановления сканер молча пропустит все ФИО и адреса в такой базе —
    то есть худший из возможных исходов для проверки по 152-ФЗ.
    """
    if not any(marker in text for marker in _MOJIBAKE_MARKERS):
        return None
    for encoding in ("cp1252", "latin-1"):
        try:
            fixed = text.encode(encoding).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if _CYRILLIC_RE.search(fixed):
            return fixed
    return None


class SourceError(Exception):
    pass


class ReadWriteAccessError(SourceError):
    """У учётной записи есть права на изменение данных."""


# --- разбор отказов подключения ---------------------------------------------

_IMAGE = "pii-scan:full"

_AUTH_MARKERS = (
    "access denied", "authentication failed", "auth failed",
    "password authentication", "wrong password", "not allowed to connect",
)
# «database » само по себе слишком широко: слово встречается и в сетевых
# сообщениях, а проверка идёт раньше разбора сети.
_DB_MARKERS = ('unknown database', 'database "', "does not exist")


class _NetworkKind(NamedTuple):
    summary: str
    detail: str
    dns: bool = False


def _network_kind(low: str) -> Optional[_NetworkKind]:
    """Три сетевых отказа выглядят похоже, а означают разное."""
    if any(m in low for m in ("name or service not known", "nodename nor",
                              "name resolution", "getaddrinfo",
                              "unknown host", "could not translate host")):
        return _NetworkKind(
            "имя хоста не разрешается",
            "DNS не вернул адрес. Сканер работает в контейнере: он не "
            "наследует /etc/hosts и resolv.conf хоста.",
            dns=True,
        )
    if "refused" in low:
        return _NetworkKind(
            "соединение отклонено",
            "Хост ответил, но порт закрыт: служба не слушает его либо "
            "слушает только на localhost.",
        )
    if any(m in low for m in ("timed out", "timeout", "unreachable",
                              "no route to host")):
        return _NetworkKind(
            "соединение не установлено, истёк таймаут",
            "Пакеты уходят без ответа. Так выглядит блокировка на "
            "межсетевом экране или отсутствие маршрута — отказ пришёл бы "
            "мгновенно.",
        )
    return None


@dataclass
class TableInfo:
    database: str
    name: str
    rows: Optional[int] = None      # оценка, COUNT(*) никогда не выполняется
    engine: str = ""
    is_view: bool = False
    order_key: str = ""    # колонка для чтения «с конца» (PK / ключ сортировки)
    schema: str = ""       # у PostgreSQL имя трёхуровневое: база.схема.таблица

    @property
    def display_name(self) -> str:
        """Имя таблицы для отчёта: со схемой там, где схемы есть."""
        return f"{self.schema}.{self.name}" if self.schema else self.name

    @property
    def qualified(self) -> str:
        return f"{self.database}.{self.display_name}"


@dataclass
class ColumnInfo:
    database: str
    table: str
    name: str
    data_type: str = ""
    comment: str = ""


@dataclass
class Sample:
    """Выборка значений: колонка -> список строковых значений (None отброшены)."""
    values: Dict[str, List[str]] = field(default_factory=dict)
    rows_read: int = 0


class Source(ABC):
    """Базовый адаптер. Открывает соединение только на чтение."""

    type: str = ""

    def __init__(self, config: SourceConfig, options: ScanOptions,
                 pacer: Optional["Pacer"] = None) -> None:
        self.config = config
        self.options = options
        self._conn = None
        self.warnings: List[str] = []   # собираются сканером в отчёт
        self.grants: List[str] = []     # сырой SHOW GRANTS — доказательство
        # Таблицы, из которых не удалось прочитать ни одного значения.
        # Молча пропустить их нельзя: в отчёте такая таблица выглядит
        # чистой, и охват обследования оказывается меньше заявленного.
        self.unreadable: List[str] = []
        # Сколько таблиц не дотянули до заданного sample_limit из-за потолка
        # трафика и какой лимит по ним реально применялся.
        self.capped_tables: int = 0
        self.capped_max: int = 0
        from ..pacing import Pacer as _Pacer
        self.pacer = pacer or _Pacer()

    @property
    def name(self) -> str:
        return self.config.name

    # --- жизненный цикл ---------------------------------------------------

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self) -> "Source":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- инвентаризация ---------------------------------------------------

    @abstractmethod
    def write_privileges(self) -> List[str]:
        """Права на запись у текущей учётной записи. Пустой список — read-only."""

    @abstractmethod
    def list_tables(self) -> List[TableInfo]: ...

    @abstractmethod
    def list_columns(self, tables: Sequence[TableInfo]) -> Dict[str, List[ColumnInfo]]:
        """Ключ словаря — TableInfo.qualified."""

    @abstractmethod
    def sample(self, table: TableInfo, columns: Sequence[ColumnInfo]) -> Sample: ...

    @abstractmethod
    def is_sampleable(self, data_type: str) -> bool:
        """Стоит ли читать значения колонки такого типа."""

    # --- общее ------------------------------------------------------------

    def readonly_account_sql(self) -> str:
        """SQL для выдачи read-only учётки — его отдают администратору БД."""
        return ""

    def check_access(self) -> List[str]:
        """Проверка read-only. Возвращает найденные права на запись."""
        try:
            privs = self.write_privileges()
        except Exception as exc:  # noqa: BLE001 — не смогли проверить, не падаем
            log.warning("[%s] не удалось проверить права: %s", self.name, exc)
            return []
        if privs and not self.options.allow_rw:
            raise ReadWriteAccessError(self._access_report(privs))
        return privs

    def _access_report(self, privs: Sequence[str]) -> str:
        """Готовый текст для администратора БД: что нашли и что нужно взамен.

        Одного перечня привилегий мало — DBA попросит подтверждение, поэтому
        приводим сырой вывод SHOW GRANTS и сразу нужный ему SQL.
        """
        lines = [
            f"учётная запись '{self.config.user}' на источнике '{self.name}' "
            f"({self.config.host}:{self.config.port}) имеет права на запись.",
            "",
            f"Найденные права: {', '.join(privs)}",
        ]
        if self.grants:
            lines += ["", "Подтверждение — вывод SHOW GRANTS:"]
            lines += [f"    {line}" for line in self.grants[:15]]
            if len(self.grants) > 15:
                lines.append(f"    … и ещё {len(self.grants) - 15} строк")

        sql = self.readonly_account_sql()
        if sql:
            lines += ["", "Что запросить у администратора БД:", ""]
            lines += [f"    {line}" for line in sql.strip().split("\n")]

        lines += [
            "",
            "Сканеру нужен только SELECT: он не делает ни одной операции "
            "записи. Если запуск под этой учётной записью — осознанное "
            "решение, добавьте --allow-rw.",
        ]
        return "\n".join(lines)

    def filtered_tables(self) -> List[TableInfo]:
        result: List[TableInfo] = []
        for table in self.list_tables():
            if not self.config.database_allowed(table.database):
                continue
            if not self.config.table_allowed(table.database, table.name):
                continue
            if table.is_view and self.config.skip_views:
                continue
            if table.engine and table.engine in self.config.skip_engines:
                continue
            result.append(table)
        return result

    @staticmethod
    def chunked(items: Sequence, size: int) -> List[Sequence]:
        return [items[i:i + size] for i in range(0, len(items), size)]

    def note_unreadable(self, table: "TableInfo", reason: str) -> None:
        """Отметить таблицу, из которой не удалось прочитать значения."""
        entry = f"{table.display_name} ({reason})"
        if entry not in self.unreadable:
            self.unreadable.append(entry)

    # --- разбор отказов подключения ---------------------------------------

    def error_text(self, exc: Exception) -> str:
        """Текст исключения драйвера в одну строку.

        Адаптер переопределяет, когда драйвер сообщает причину числовым
        кодом вместо слов.
        """
        return " ".join(str(exc).split())

    def connect_error(self, exc: Exception, extra: str = "") -> "SourceError":
        """Причина отказа вместо сырого исключения драйвера.

        Драйверы сообщают об одном и том же по-разному: PyMySQL отдаёт кортеж
        `(2003, "Can't connect ... (timed out)")`, psycopg — многострочный
        текст, clickhouse-driver — «Code: 209». Читателю нужно одно: что
        именно не сложилось и куда смотреть.
        """
        cfg = self.config
        text = self.error_text(exc)
        where = f"{cfg.host}:{cfg.port}"
        low = text.lower()

        if any(m in low for m in _AUTH_MARKERS):
            return SourceError(
                f"{where}: учётная запись '{cfg.user}' не принята — неверный "
                f"пароль либо вход с этого адреса не разрешён.\n"
                f"Драйвер сообщает: {text}"
            )
        if any(m in low for m in _DB_MARKERS):
            return SourceError(
                f"{where}: база из конфига недоступна учётной записи "
                f"'{cfg.user}'.\nДрайвер сообщает: {text}"
            )

        kind = _network_kind(low)
        if not kind:
            return SourceError(f"{where}: {text}")

        lines = [f"{where}: {kind.summary}", kind.detail, "Что проверить:"]
        if kind.dns:
            lines.append(f"  1) имя разрешается ли из контейнера: "
                         f"docker run --rm {_IMAGE} getent hosts {cfg.host}")
        else:
            lines.append(f"  1) доступен ли порт:  nc -zv {cfg.host} {cfg.port}")
        lines.append("  2) сканер работает в контейнере — у него своя сеть, "
                     "свой DNS и свои маршруты. С хоста база может быть "
                     "видна, а из контейнера нет")
        lines.append("     см. «Подключение по сети» в README")
        if extra:
            lines.append(extra)
        lines.append(f"  3) правила межсетевого экрана до {cfg.host}")
        return SourceError("\n".join(lines))

    def sample_parts(self, limit: int, has_order_key: bool) -> List[tuple]:
        """Разбивает выборку на части: [(сколько строк, читать ли с конца)].

        Чтение только «головы» таблицы — систематическая слепая зона: поле,
        которое начали заполнять недавно, в старых строках пусто, и сканер
        объявит его чистым. Поэтому по умолчанию половина выборки берётся
        с конца, по ключу сортировки.
        """
        strategy = getattr(self.options, "sample_strategy", "head")
        if strategy == "head" or not has_order_key:
            return [(limit, False)]
        if strategy == "tail":
            return [(limit, True)]
        head = max(1, limit // 2)
        return [(head, False), (limit - head, True)]

    def effective_limit(self, columns: Sequence[ColumnInfo]) -> int:
        """Сколько строк читать с учётом ширины таблицы.

        У таблицы на 300 колонок выборка в 500 строк — это десятки мегабайт
        по сети на каждую таблицу. Ограничиваем трафик, а не число строк:
        оценка среднего значения берётся как восьмая часть от потолка длины
        (max_value_len), значения в жизни куда короче своего максимума.
        """
        limit = int(self.options.sample_limit)
        budget = int(self.options.max_bytes_per_table)
        if budget <= 0 or not columns:
            return limit
        per_row = max(1, len(columns) * max(8, self.options.max_value_len // 8))
        allowed = max(50, budget // per_row)
        if allowed < limit:
            # Заданный лимит недостижим — это надо сказать вслух. Иначе
            # «--limit 20000» выглядит применённым, а читается втрое меньше,
            # и о том, что упёрлись в трафик, знает только debug-журнал.
            log.debug("[%s] выборка уменьшена до %d строк (%d колонок)",
                      self.name, allowed, len(columns))
            self.capped_tables += 1
            self.capped_max = max(self.capped_max, allowed)
        return min(limit, allowed)

    def limit_capped_note(self) -> str:
        """Предупреждение о недостижимом лимите — пусто, если всё прочиталось."""
        if not self.capped_tables:
            return ""
        mb = self.options.max_bytes_per_table / 1_000_000
        return (
            f"[{self.name}] задано {self.options.sample_limit} строк на "
            f"таблицу, но выборка ограничена трафиком "
            f"(max_bytes_per_table = {mb:g} МБ): в {self.capped_tables} "
            f"таблицах прочитано не более {self.capped_max} строк. "
            f"Чтобы читать больше, поднимайте max_bytes_per_table вместе с "
            f"--limit — широкая таблица иначе вытянет по сети десятки "
            f"мегабайт."
        )


def build_source(config: SourceConfig, options: ScanOptions,
                 pacer=None) -> Source:
    if config.type == "mysql":
        from .mysql import MySQLSource
        return MySQLSource(config, options, pacer)
    if config.type == "postgres":
        from .postgres import PostgresSource
        return PostgresSource(config, options, pacer)
    if config.type == "clickhouse":
        from .clickhouse import ClickHouseSource
        return ClickHouseSource(config, options, pacer)
    raise SourceError(f"неизвестный тип источника: {config.type}")
