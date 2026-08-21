# -*- coding: utf-8 -*-
"""Протокол источника данных.

Ядро сканера не знает ни одного диалекта SQL: всё, что специфично для СУБД,
живёт в адаптере. Добавить PostgreSQL или Oracle = добавить один файл.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..config import ScanOptions, SourceConfig

log = logging.getLogger(__name__)


class SourceError(Exception):
    pass


class ReadWriteAccessError(SourceError):
    """У учётной записи есть права на изменение данных."""


@dataclass
class TableInfo:
    database: str
    name: str
    rows: Optional[int] = None      # оценка, COUNT(*) никогда не выполняется
    engine: str = ""
    is_view: bool = False

    @property
    def qualified(self) -> str:
        return f"{self.database}.{self.name}"


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

    def __init__(self, config: SourceConfig, options: ScanOptions) -> None:
        self.config = config
        self.options = options
        self._conn = None

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

    def check_access(self) -> List[str]:
        """Проверка read-only. Возвращает найденные права на запись."""
        try:
            privs = self.write_privileges()
        except Exception as exc:  # noqa: BLE001 — не смогли проверить, не падаем
            log.warning("[%s] не удалось проверить права: %s", self.name, exc)
            return []
        if privs and not self.options.allow_rw:
            raise ReadWriteAccessError(
                f"учётная запись '{self.config.user}' на источнике "
                f"'{self.name}' имеет права на запись: {', '.join(privs)}.\n"
                f"Сканеру нужен только SELECT. Выдайте read-only учётку либо "
                f"запустите с --allow-rw, если это осознанное решение."
            )
        return privs

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


def build_source(config: SourceConfig, options: ScanOptions) -> Source:
    if config.type == "mysql":
        from .mysql import MySQLSource
        return MySQLSource(config, options)
    if config.type == "clickhouse":
        from .clickhouse import ClickHouseSource
        return ClickHouseSource(config, options)
    raise SourceError(f"неизвестный тип источника: {config.type}")
