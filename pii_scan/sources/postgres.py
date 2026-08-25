# -*- coding: utf-8 -*-
"""Адаптер PostgreSQL.

Две особенности, которых нет у MySQL и ClickHouse:

  * **Соединение привязано к одной базе.** Межбазовых запросов в PostgreSQL
    нет, поэтому на каждую обследуемую базу открывается своё подключение.
  * **Трёхуровневые имена** база.схема.таблица. Схема попадает в отчёт, иначе
    public.clients и billing.clients слились бы в одну строку.

Безопасность прод-сканирования:
  * размер таблицы берётся из pg_class.reltuples — оценка планировщика,
    COUNT(*) не выполняется;
  * statement_timeout ограничивает каждый запрос на стороне сервера;
  * значения обрезаются там же через left(col::text, N);
  * выборка идёт по первичному ключу, без ORDER BY по неиндексированному полю.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Sequence

from .base import (
    ColumnInfo, Sample, Source, SourceError, TableInfo, repair_mojibake,
)

log = logging.getLogger(__name__)

# Служебные схемы: собственных данных там нет
SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast")
_SYSTEM_SCHEMAS_SQL = "(" + ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS) + ")"

# Типы, значения которых читать бессмысленно или дорого
SKIP_TYPES = {
    "bytea", "tsvector", "tsquery", "pg_lsn", "txid_snapshot",
    "geometry", "geography", "raster",
}

WRITE_PRIVS = ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
               "TRIGGER", "CREATE")

# Приставка psycopg, одинаковая для всех баз одного сервера
_CONN_PREFIX_RE = re.compile(
    r"^\s*connection failed: connection to server at [^:]+:?[^\n]*failed:\s*",
    re.I)


def _skip_reason(exc: Exception) -> str:
    """Короткая причина, по которой база не открылась.

    psycopg отдаёт многострочный текст: адрес сервера, локализованное
    «ВАЖНО:» и отдельной строкой DETAIL. Адрес одинаков для всех баз
    сервера, имя базы уже названо рядом — остаётся суть.
    """
    text = _CONN_PREFIX_RE.sub("", str(exc)).strip()
    head = text.split("\n")[0].strip()
    for label in ("ВАЖНО:", "FATAL:", "ОШИБКА:", "ERROR:"):
        if head.startswith(label):
            head = head[len(label):].strip()
    detail = ""
    for line in text.split("\n")[1:]:
        low = line.strip()
        if low.startswith(("DETAIL:", "ПОДРОБНОСТИ:")):
            detail = low.split(":", 1)[1].strip()
            break
    # Имя базы в тексте ошибки лишнее: базы перечисляются рядом списком
    head = re.sub(r'"[^"]+"', "", head).replace("  ", " ").strip()
    return f"{head} ({detail})" if detail else head or str(exc)[:120]


def _quote(ident: str) -> str:
    """Двойные кавычки; внутренние удваиваются."""
    if not ident or any(ord(ch) < 32 for ch in ident):
        raise SourceError(f"недопустимый идентификатор: {ident!r}")
    return '"' + ident.replace('"', '""') + '"'


def parse_write_privileges(rows: Sequence[Sequence]) -> List[str]:
    """Разбирает привилегии из information_schema.role_table_grants."""
    found: List[str] = []
    for row in rows:
        priv = str(row[0]).strip().upper()
        if priv in WRITE_PRIVS and priv not in found:
            found.append(priv)
    return found


class PostgresSource(Source):
    type = "postgres"

    def __init__(self, config, options, pacer=None) -> None:
        super().__init__(config, options, pacer)
        self._conns: Dict[str, object] = {}
        self._driver = ""
        self._entry_db = ""
        # причина -> базы, которые по ней не открылись
        self._skipped: Dict[str, List[str]] = {}

    # --- жизненный цикл ---------------------------------------------------

    def _connect_to(self, database: str):
        cfg = self.config
        params = dict(
            host=cfg.host, port=cfg.port, user=cfg.user,
            password=cfg.password or None, dbname=database,
            connect_timeout=max(self.options.query_timeout, 5),
        )
        if cfg.secure:
            params["sslmode"] = "verify-full" if cfg.ssl_verify else "require"
            if cfg.ssl_ca:
                params["sslrootcert"] = cfg.ssl_ca

        try:
            import psycopg
            conn = psycopg.connect(autocommit=True, **params)
            self._driver = self._driver or "psycopg3"
        except ImportError:
            try:
                import psycopg2
            except ImportError as exc:
                raise SourceError(
                    "не установлен драйвер PostgreSQL (нужен psycopg или "
                    "psycopg2)"
                ) from exc
            conn = psycopg2.connect(**params)
            conn.autocommit = True
            self._driver = self._driver or "psycopg2"

        # Таймаут на стороне сервера: запрос не переживёт сканер
        cur = conn.cursor()
        cur.execute(f"SET statement_timeout = {self.options.query_timeout * 1000}")
        for name, value in (self.config.settings or {}).items():
            literal = value if isinstance(value, (int, float)) else f"'{value}'"
            try:
                cur.execute(f"SET {name} = {literal}")
            except Exception as exc:  # noqa: BLE001
                self.warnings.append(
                    f"[{self.name}] не удалось задать {name}={value}: {exc}")
        cur.close()
        return conn

    def connect(self) -> None:
        # Входная база: явно заданная первой в конфиге либо служебная postgres
        self._entry_db = (self.config.databases or ["postgres"])[0]
        try:
            self._conns[self._entry_db] = self._connect_to(self._entry_db)
        except SourceError:
            raise
        except Exception as exc:  # noqa: BLE001 — отказ драйвера, а не сбой
            raise self.connect_error(
                exc,
                f"  * если база называется иначе, укажите её в databases: "
                f"сейчас вход идёт через '{self._entry_db}'"
            ) from exc
        self._conn = self._conns[self._entry_db]
        log.info("[%s] подключение к PostgreSQL %s:%s/%s установлено (%s)",
                 self.name, self.config.host, self.config.port,
                 self._entry_db, self._driver)

    def close(self) -> None:
        for conn in self._conns.values():
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        self._conns.clear()
        self._conn = None

    def _conn_for(self, database: str):
        if database not in self._conns:
            self._conns[database] = self._connect_to(database)
        return self._conns[database]

    def _query(self, sql: str, database: Optional[str] = None,
               params: Sequence = ()) -> List[tuple]:
        self.pacer.before_query()
        conn = self._conn_for(database) if database else self._conn
        cur = conn.cursor()
        try:
            cur.execute(sql, params or None)
            rows = cur.fetchall()
        finally:
            cur.close()
        return [tuple(row) for row in rows or []]

    # --- инвентаризация ---------------------------------------------------

    def write_privileges(self) -> List[str]:
        self.grants = []
        found: List[str] = []

        # Суперпользователь может всё, отдельные гранты уже неважны
        try:
            rows = self._query(
                "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles "
                "WHERE rolname = current_user"
            )
            if rows:
                is_super, can_createdb, can_createrole = rows[0]
                if is_super:
                    self.grants.append(
                        f"роль {self.config.user}: SUPERUSER")
                    found.append("SUPERUSER")
                if can_createdb:
                    self.grants.append(f"роль {self.config.user}: CREATEDB")
                    found.append("CREATEDB")
                if can_createrole:
                    self.grants.append(f"роль {self.config.user}: CREATEROLE")
                    found.append("CREATEROLE")
        except Exception as exc:  # noqa: BLE001
            log.debug("[%s] не удалось прочитать pg_roles: %s", self.name, exc)

        try:
            rows = self._query(
                "SELECT DISTINCT privilege_type, table_schema "
                "FROM information_schema.role_table_grants "
                "WHERE grantee = current_user "
                "AND table_schema NOT IN ('pg_catalog', 'information_schema') "
                "ORDER BY privilege_type"
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("[%s] не удалось прочитать гранты: %s", self.name, exc)
            rows = []

        for priv, schema in rows:
            self.grants.append(f"GRANT {priv} ON схему {schema} TO "
                               f"{self.config.user}")
        for priv in parse_write_privileges(rows):
            if priv not in found:
                found.append(priv)
        return found

    def readonly_account_sql(self) -> str:
        return "\n".join([
            "CREATE ROLE pii_reader LOGIN PASSWORD '<надёжный_пароль>';",
            "-- в каждой обследуемой базе:",
            "GRANT CONNECT ON DATABASE имя_базы TO pii_reader;",
            "GRANT USAGE ON SCHEMA public TO pii_reader;",
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO pii_reader;",
            "-- чтобы новые таблицы тоже были видны:",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public",
            "    GRANT SELECT ON TABLES TO pii_reader;",
        ])

    def _databases(self) -> List[str]:
        """Базы, к которым разрешено подключаться."""
        if self.config.databases:
            return list(self.config.databases)
        rows = self._query(
            "SELECT datname FROM pg_database "
            "WHERE datallowconn AND NOT datistemplate ORDER BY datname"
        )
        return [row[0] for row in rows]

    def list_tables(self) -> List[TableInfo]:
        tables: List[TableInfo] = []
        for database in self._databases():
            if not self.config.database_allowed(database):
                continue
            try:
                rows = self._query(
                    "SELECT n.nspname, c.relname, c.relkind, "
                    "       CASE WHEN c.reltuples < 0 THEN NULL "
                    "            ELSE c.reltuples::bigint END "
                    "FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') "
                    f"AND n.nspname NOT IN {_SYSTEM_SCHEMAS_SQL} "
                    "AND n.nspname NOT LIKE 'pg_temp%'",
                    database=database,
                )
            except Exception as exc:  # noqa: BLE001
                # На сервере с сотней баз недоступных обычно десятки, и по
                # строке на каждую — это экран текста с одной и той же
                # причиной. Копим и объявляем одним пунктом.
                self._skipped.setdefault(_skip_reason(exc), []).append(database)
                continue

            keys = self._primary_keys(database)
            for schema, name, relkind, reltuples in rows:
                tables.append(TableInfo(
                    database=database, schema=schema, name=name,
                    rows=int(reltuples) if reltuples is not None else None,
                    engine="materialized view" if relkind == "m" else "",
                    is_view=relkind in ("v", "m"),
                    order_key=keys.get(f"{schema}.{name}", ""),
                ))
        self._report_skipped()
        return tables

    def _report_skipped(self) -> None:
        """Недоступные базы — одна строка на причину, а не на базу.

        Это ещё и разрыв в охвате: обследовано меньше, чем есть на сервере,
        и в отчёте это должно быть видно.
        """
        for reason, names in self._skipped.items():
            names.sort()
            self.skipped_databases.extend(names)
            shown = ", ".join(names[:8])
            tail = f" … и ещё {len(names) - 8}" if len(names) > 8 else ""
            self.warnings.append(
                f"[{self.name}] баз пропущено: {len(names)} — {reason}. "
                f"Эти базы не обследованы: {shown}{tail}"
            )

    def _primary_keys(self, database: str) -> Dict[str, str]:
        """Первая колонка первичного ключа — по ней читается «хвост»."""
        try:
            rows = self._query(
                "SELECT n.nspname, c.relname, a.attname "
                "FROM pg_index i "
                "JOIN pg_class c ON c.oid = i.indrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid = c.oid "
                "     AND a.attnum = i.indkey[0] "
                "WHERE i.indisprimary",
                database=database,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("[%s] первичные ключи %s: %s", self.name, database, exc)
            return {}
        return {f"{schema}.{table}": column for schema, table, column in rows}

    def list_columns(self, tables: Sequence[TableInfo]) -> Dict[str, List[ColumnInfo]]:
        result: Dict[str, List[ColumnInfo]] = {}
        wanted = {t.qualified for t in tables}
        for database in sorted({t.database for t in tables}):
            try:
                rows = self._query(
                    "SELECT n.nspname, c.relname, a.attname, "
                    "       format_type(a.atttypid, NULL), "
                    "       col_description(c.oid, a.attnum) "
                    "FROM pg_attribute a "
                    "JOIN pg_class c ON c.oid = a.attrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE a.attnum > 0 AND NOT a.attisdropped "
                    "AND c.relkind IN ('r', 'p', 'v', 'm', 'f') "
                    f"AND n.nspname NOT IN {_SYSTEM_SCHEMAS_SQL} "
                    "ORDER BY n.nspname, c.relname, a.attnum",
                    database=database,
                )
            except Exception as exc:  # noqa: BLE001
                self.warnings.append(
                    f"[{self.name}] колонки базы {database}: {exc}")
                continue

            for schema, table, column, data_type, comment in rows:
                key = f"{database}.{schema}.{table}"
                if key not in wanted:
                    continue
                result.setdefault(key, []).append(ColumnInfo(
                    database=database, table=f"{schema}.{table}", name=column,
                    data_type=(data_type or "").lower(), comment=comment or "",
                ))
        return result

    def is_sampleable(self, data_type: str) -> bool:
        base = data_type.split("(")[0].strip().lower()
        return base not in SKIP_TYPES

    # --- выборка ----------------------------------------------------------

    def sample(self, table: TableInfo, columns: Sequence[ColumnInfo]) -> Sample:
        result = Sample()
        target = [c for c in columns if self.is_sampleable(c.data_type)]
        if not target:
            return result

        limit = self.effective_limit(target)
        maxlen = int(self.options.max_value_len)
        qualified = f"{_quote(table.schema)}.{_quote(table.name)}"
        parts = self.sample_parts(limit, bool(table.order_key))

        for chunk in self.chunked(target, self.options.max_columns_per_query):
            select = ", ".join(
                f"left({_quote(c.name)}::text, {maxlen}) AS c{i}"
                for i, c in enumerate(chunk)
            )
            rows: List[tuple] = []
            for part_limit, from_tail in parts:
                sql = f"SELECT {select} FROM {qualified}"
                if from_tail:
                    sql += f" ORDER BY {_quote(table.order_key)} DESC"
                sql += f" LIMIT {part_limit}"
                try:
                    part_rows = self._query(sql, database=table.database)
                except Exception as exc:  # noqa: BLE001
                    log.warning("[%s] %s: выборка не удалась (%s)",
                                self.name, table.qualified, exc)
                    continue
                rows.extend(part_rows)
                if len(part_rows) < part_limit:
                    # Таблица меньше выборки — «хвост» вернёт те же строки
                    break
            if not rows:
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
                    fixed = repair_mojibake(text)
                    if fixed is not None:
                        text = fixed
                    if text.strip():
                        bucket.append(text)
        return result
