# -*- coding: utf-8 -*-
"""Адаптер MySQL / MariaDB.

Безопасность прод-сканирования:
  * COUNT(*) не выполняется никогда — размер берётся из information_schema;
  * одна выборка на таблицу, а не на колонку;
  * значения обрезаются на стороне сервера (LEFT(CAST(...))), по сети не едут
    мегабайтные тексты;
  * жёсткий таймаут запроса (MAX_EXECUTION_TIME / max_statement_time);
  * никаких ORDER BY RAND() — только LIMIT.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Sequence

from .base import ColumnInfo, Sample, Source, SourceError, TableInfo

log = logging.getLogger(__name__)

# Типы, значения которых читать бессмысленно или дорого.
SKIP_TYPES = {
    "blob", "tinyblob", "mediumblob", "longblob",
    "binary", "varbinary", "bit",
    "geometry", "point", "linestring", "polygon",
    "multipoint", "multilinestring", "multipolygon", "geometrycollection",
}

WRITE_PRIVS = (
    "ALL PRIVILEGES", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
    "CREATE", "TRUNCATE", "REPLACE", "LOAD", "GRANT OPTION",
)

_IDENT_RE = re.compile(r"^[\w$-￿]+$")


def _quote(ident: str) -> str:
    """Обратные кавычки. Идентификаторы приходят из information_schema,
    но проверяем всё равно — защита от инъекции через имя объекта."""
    if not _IDENT_RE.match(ident):
        raise SourceError(f"недопустимый идентификатор: {ident!r}")
    return f"`{ident}`"


class MySQLSource(Source):
    type = "mysql"

    def connect(self) -> None:
        cfg = self.config
        timeout = max(self.options.query_timeout, 5)
        try:
            import pymysql
            ssl_args = {}
            if cfg.secure:
                ssl_conf = {}
                if cfg.ssl_ca:
                    ssl_conf["ca"] = cfg.ssl_ca
                if not cfg.ssl_verify:
                    ssl_conf["check_hostname"] = False
                    ssl_conf["verify_mode"] = False
                ssl_args["ssl"] = ssl_conf
            self._conn = pymysql.connect(
                host=cfg.host, port=cfg.port, user=cfg.user, password=cfg.password,
                charset="utf8mb4", connect_timeout=timeout, read_timeout=timeout * 4,
                autocommit=True, **ssl_args,
            )
            self._driver = "pymysql"
        except ImportError:
            try:
                import mysql.connector as mysql_connector
            except ImportError as exc:
                raise SourceError(
                    "не установлен драйвер MySQL (нужен PyMySQL или "
                    "mysql-connector-python)"
                ) from exc
            self._conn = mysql_connector.connect(
                host=cfg.host, port=cfg.port, user=cfg.user, password=cfg.password,
                charset="utf8mb4", connection_timeout=timeout, autocommit=True,
                ssl_disabled=not cfg.secure,
                ssl_ca=cfg.ssl_ca or None,
                ssl_verify_cert=cfg.secure and cfg.ssl_verify,
            )
            self._driver = "mysql-connector"
        self._apply_timeout()
        log.info("[%s] подключение к MySQL %s:%s установлено (%s)",
                 self.name, cfg.host, cfg.port, self._driver)

    def _apply_timeout(self) -> None:
        ms = self.options.query_timeout * 1000
        for stmt in (f"SET SESSION MAX_EXECUTION_TIME={ms}",          # MySQL 5.7.8+
                     f"SET SESSION max_statement_time={ms / 1000}"):  # MariaDB
            try:
                self._execute(stmt)
                return
            except Exception:  # noqa: BLE001 — старые версии не знают ни того, ни другого
                continue
        log.debug("[%s] таймаут запроса на стороне сервера не поддерживается",
                  self.name)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    # --- низкий уровень ---------------------------------------------------

    def _execute(self, sql: str, params=None) -> List[tuple]:
        cur = self._conn.cursor()
        try:
            cur.execute(sql, params or ())
            rows = cur.fetchall()
        finally:
            cur.close()
        return list(rows or [])

    # --- инвентаризация ---------------------------------------------------

    def write_privileges(self) -> List[str]:
        found: List[str] = []
        for (grant,) in self._execute("SHOW GRANTS FOR CURRENT_USER()"):
            head = grant.split(" ON ", 1)[0].upper()
            for priv in WRITE_PRIVS:
                if priv in head and priv not in found:
                    found.append(priv)
        return found

    def list_tables(self) -> List[TableInfo]:
        rows = self._execute(
            "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_ROWS, TABLE_TYPE, ENGINE "
            "FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA NOT IN "
            "('mysql','information_schema','performance_schema','sys')"
        )
        return [
            TableInfo(
                database=db, name=name,
                rows=int(rows_est) if rows_est is not None else None,
                engine=engine or "",
                is_view=(ttype or "").upper() == "VIEW",
            )
            for db, name, rows_est, ttype, engine in rows
        ]

    def list_columns(self, tables: Sequence[TableInfo]) -> Dict[str, List[ColumnInfo]]:
        if not tables:
            return {}
        schemas = sorted({t.database for t in tables})
        placeholders = ", ".join(["%s"] * len(schemas))
        rows = self._execute(
            "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, COLUMN_COMMENT "
            "FROM information_schema.COLUMNS "
            f"WHERE TABLE_SCHEMA IN ({placeholders}) "
            "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION",
            schemas,
        )
        wanted = {t.qualified for t in tables}
        result: Dict[str, List[ColumnInfo]] = {}
        for db, table, column, dtype, comment in rows:
            key = f"{db}.{table}"
            if key not in wanted:
                continue
            result.setdefault(key, []).append(
                ColumnInfo(database=db, table=table, name=column,
                           data_type=(dtype or "").lower(), comment=comment or "")
            )
        return result

    def is_sampleable(self, data_type: str) -> bool:
        return data_type.lower() not in SKIP_TYPES

    # --- выборка ----------------------------------------------------------

    def sample(self, table: TableInfo, columns: Sequence[ColumnInfo]) -> Sample:
        result = Sample()
        target = [c for c in columns if self.is_sampleable(c.data_type)]
        if not target:
            return result

        limit = int(self.options.sample_limit)
        maxlen = int(self.options.max_value_len)
        qualified = f"{_quote(table.database)}.{_quote(table.name)}"

        for chunk in self.chunked(target, self.options.max_columns_per_query):
            select = ", ".join(
                f"LEFT(CAST({_quote(c.name)} AS CHAR), {maxlen}) AS c{i}"
                for i, c in enumerate(chunk)
            )
            sql = f"SELECT {select} FROM {qualified} LIMIT {limit}"
            try:
                rows = self._execute(sql)
            except Exception as exc:  # noqa: BLE001
                log.warning("[%s] %s: выборка не удалась (%s)",
                            self.name, table.qualified, exc)
                continue
            result.rows_read = max(result.rows_read, len(rows))
            for idx, col in enumerate(chunk):
                bucket = result.values.setdefault(col.name, [])
                for row in rows:
                    value = row[idx]
                    if value is None:
                        continue
                    text = value.decode("utf-8", "replace") if isinstance(
                        value, (bytes, bytearray)) else str(value)
                    if text.strip():
                        bucket.append(text)
        return result
