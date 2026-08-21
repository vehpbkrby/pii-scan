# -*- coding: utf-8 -*-
"""Адаптер ClickHouse.

Работает через clickhouse-connect (HTTP, порт 8123) либо, если его нет, через
clickhouse-driver (нативный протокол, порт 9000).

Безопасность прод-сканирования:
  * размер таблицы берётся из system.tables.total_rows, COUNT(*) не делается;
  * max_execution_time и max_threads ограничены на уровне сессии;
  * значения обрезаются на сервере через substring(toString(col), 1, N);
  * по умолчанию пропускаются Distributed/Merge/View — иначе те же данные
    попадут в отчёт по нескольку раз.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Sequence

from .base import ColumnInfo, Sample, Source, SourceError, TableInfo

log = logging.getLogger(__name__)

WRITE_PRIVS = (
    "ALL", "INSERT", "ALTER", "CREATE", "DROP", "TRUNCATE", "OPTIMIZE",
    "SYSTEM", "GRANT",
)

VIEW_ENGINES = {"View", "MaterializedView", "LiveView", "WindowView"}

# Управляющие символы в имени объекта — признак повреждённых метаданных
_BAD_IDENT_CHARS = frozenset(chr(c) for c in range(32)) | {chr(127)}


def _quote(ident: str) -> str:
    """Экранирование имени объекта.

    Имена приходят из системных таблиц, но подставляются в текст запроса,
    поэтому экранируются как положено: внутренние обратные кавычки
    удваиваются. Точки в именах допустимы — так называются служебные
    таблицы ClickHouse (.inner_id.*).
    """
    if not ident or _BAD_IDENT_CHARS & set(ident):
        raise SourceError(f"недопустимый идентификатор: {ident!r}")
    return "`" + ident.replace("`", "``") + "`"


def _lit(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


class ClickHouseSource(Source):
    type = "clickhouse"

    def __init__(self, config, options, pacer=None) -> None:
        super().__init__(config, options, pacer)
        self._driver = ""

    # --- жизненный цикл ---------------------------------------------------

    def connect(self) -> None:
        cfg = self.config
        settings = {
            "max_execution_time": int(self.options.query_timeout),
            "max_threads": int(self.options.max_threads),
        }
        # Родные ограничители ClickHouse: max_bytes_to_read,
        # max_execution_speed_bytes, max_memory_usage, priority и прочее
        settings.update(self.config.settings or {})
        try:
            import clickhouse_connect
            tls = {}
            if cfg.secure:
                tls["verify"] = cfg.ssl_verify
                if cfg.ssl_ca:
                    tls["ca_cert"] = cfg.ssl_ca
            self._conn = clickhouse_connect.get_client(
                host=cfg.host, port=cfg.port, username=cfg.user,
                password=cfg.password, secure=cfg.secure,
                connect_timeout=max(self.options.query_timeout, 5),
                send_receive_timeout=self.options.query_timeout * 4,
                settings=settings, **tls,
            )
            self._driver = "clickhouse-connect"
        except ImportError:
            try:
                from clickhouse_driver import Client
            except ImportError as exc:
                raise SourceError(
                    "не установлен драйвер ClickHouse (нужен clickhouse-connect "
                    "или clickhouse-driver)"
                ) from exc
            port = cfg.port if cfg.port not in (8123, 8443) else 9000
            self._conn = Client(
                host=cfg.host, port=port, user=cfg.user, password=cfg.password,
                secure=cfg.secure, settings=settings,
                connect_timeout=max(self.options.query_timeout, 5),
                verify=cfg.ssl_verify, ca_certs=cfg.ssl_ca or None,
            )
            self._driver = "clickhouse-driver"
        log.info("[%s] подключение к ClickHouse %s:%s установлено (%s)",
                 self.name, cfg.host, cfg.port, self._driver)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def _query(self, sql: str) -> List[tuple]:
        self.pacer.before_query()
        if self._driver == "clickhouse-connect":
            return [tuple(row) for row in self._conn.query(sql).result_rows]
        return [tuple(row) for row in self._conn.execute(sql)]

    # --- инвентаризация ---------------------------------------------------

    def write_privileges(self) -> List[str]:
        found: List[str] = []
        try:
            rows = self._query("SHOW GRANTS")
        except Exception:  # noqa: BLE001 — у пользователя может не быть доступа
            rows = []
        for row in rows:
            grant = str(row[0]).upper()
            head = grant.split(" ON ", 1)[0]
            for priv in WRITE_PRIVS:
                if re.search(rf"\b{priv}\b", head) and priv not in found:
                    found.append(priv)
        if found:
            # readonly=1/2 на уровне профиля перекрывает выданные гранты
            try:
                ro = self._query(
                    "SELECT value FROM system.settings WHERE name = 'readonly'"
                )
                if ro and str(ro[0][0]) in ("1", "2"):
                    log.info("[%s] профиль пользователя readonly=%s — запись "
                             "фактически запрещена", self.name, ro[0][0])
                    return []
            except Exception:  # noqa: BLE001
                pass
        return found

    def list_tables(self) -> List[TableInfo]:
        rows = self._query(
            "SELECT database, name, engine, total_rows FROM system.tables "
            "WHERE database NOT IN "
            "('system', 'INFORMATION_SCHEMA', 'information_schema') "
            "AND is_temporary = 0"
        )
        return [
            TableInfo(
                database=db, name=name, engine=engine or "",
                rows=int(total) if total is not None else None,
                is_view=(engine in VIEW_ENGINES),
            )
            for db, name, engine, total in rows
            # .inner_id.* — внутреннее хранилище материализованных
            # представлений, дублирует данные исходной таблицы
            if not name.startswith(".inner")
        ]

    def list_columns(self, tables: Sequence[TableInfo]) -> Dict[str, List[ColumnInfo]]:
        if not tables:
            return {}
        dbs = ", ".join(_lit(d) for d in sorted({t.database for t in tables}))
        rows = self._query(
            "SELECT database, table, name, type, comment FROM system.columns "
            f"WHERE database IN ({dbs}) ORDER BY database, table, position"
        )
        wanted = {t.qualified for t in tables}
        result: Dict[str, List[ColumnInfo]] = {}
        for db, table, column, dtype, comment in rows:
            key = f"{db}.{table}"
            if key not in wanted:
                continue
            result.setdefault(key, []).append(
                ColumnInfo(database=db, table=table, name=column,
                           data_type=dtype or "", comment=comment or "")
            )
        return result

    def is_sampleable(self, data_type: str) -> bool:
        # Состояния агрегатных функций в строку не разворачиваются
        return not data_type.startswith(("AggregateFunction", "SimpleAggregateFunction"))

    # --- выборка ----------------------------------------------------------

    def sample(self, table: TableInfo, columns: Sequence[ColumnInfo]) -> Sample:
        result = Sample()
        target = [c for c in columns if self.is_sampleable(c.data_type)]
        if not target:
            return result

        limit = self.effective_limit(target)
        maxlen = int(self.options.max_value_len)
        qualified = f"{_quote(table.database)}.{_quote(table.name)}"

        for chunk in self.chunked(target, self.options.max_columns_per_query):
            select = ", ".join(
                f"substring(toString({_quote(c.name)}), 1, {maxlen}) AS c{i}"
                for i, c in enumerate(chunk)
            )
            sql = f"SELECT {select} FROM {qualified} LIMIT {limit}"
            try:
                rows = self._query(sql)
            except Exception as exc:  # noqa: BLE001
                log.warning("[%s] %s: групповая выборка не удалась (%s), "
                            "пробую по колонкам", self.name, table.qualified, exc)
                rows = []
                self._sample_one_by_one(qualified, chunk, limit, maxlen, result)
                continue
            result.rows_read = max(result.rows_read, len(rows))
            for idx, col in enumerate(chunk):
                bucket = result.values.setdefault(col.name, [])
                for row in rows:
                    value = row[idx]
                    if value is None:
                        continue
                    text = str(value)
                    if text.strip():
                        bucket.append(text)
        return result

    def _sample_one_by_one(self, qualified: str, chunk, limit: int,
                           maxlen: int, result: Sample) -> None:
        """Запасной путь: одна экзотическая колонка не должна ронять всю таблицу."""
        for col in chunk:
            sql = (f"SELECT substring(toString({_quote(col.name)}), 1, {maxlen}) "
                   f"FROM {qualified} LIMIT {limit}")
            try:
                rows = self._query(sql)
            except Exception as exc:  # noqa: BLE001
                log.debug("[%s] колонка %s пропущена: %s", self.name, col.name, exc)
                continue
            result.rows_read = max(result.rows_read, len(rows))
            bucket = result.values.setdefault(col.name, [])
            for row in rows:
                if row[0] is not None and str(row[0]).strip():
                    bucket.append(str(row[0]))
