# -*- coding: utf-8 -*-
"""Разбор вывода SHOW GRANTS.

Блокировка запуска опирается на этот разбор, поэтому цена ошибки высокая
в обе стороны: ложное срабатывание не даёт работать честной read-only
учётке, пропуск — допускает сканирование под административной.
"""
from __future__ import annotations

from pii_scan.sources.clickhouse import parse_write_privileges as ch_parse
from pii_scan.sources.mysql import parse_write_privileges as my_parse


# --- MySQL ------------------------------------------------------------------

def test_mysql_readonly_account_is_clean():
    grants = [
        "GRANT SELECT ON *.* TO `pii_reader`@`%`",
        "GRANT USAGE ON *.* TO `pii_reader`@`%`",
    ]
    assert my_parse(grants) == []


def test_mysql_detects_write():
    grants = [
        "GRANT USAGE ON *.* TO `app_rw`@`%`",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON `crm`.* TO `app_rw`@`%`",
    ]
    found = my_parse(grants)
    assert set(found) == {"INSERT", "UPDATE", "DELETE"}


def test_mysql_detects_all_privileges():
    assert "ALL PRIVILEGES" in my_parse(
        ["GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost`"])


def test_mysql_detects_grant_option():
    """Право раздавать доступ видно по хвосту, а не по началу строки."""
    grants = ["GRANT SELECT ON *.* TO `boss`@`%` WITH GRANT OPTION"]
    assert my_parse(grants) == ["GRANT OPTION"]


def test_mysql_select_on_database_with_grant_in_name():
    """Слово из имени базы не должно превращаться в привилегию."""
    assert my_parse(["GRANT SELECT ON `grants_db`.* TO `pii_reader`@`%`"]) == []


# --- ClickHouse -------------------------------------------------------------

def test_clickhouse_readonly_account_is_clean():
    """Ключевое слово GRANT начинает каждую строку и правом не является."""
    assert ch_parse(["GRANT SELECT ON *.* TO pii_reader"]) == []


def test_clickhouse_detects_write():
    found = ch_parse(["GRANT SELECT, INSERT ON analytics.* TO etl_writer"])
    assert found == ["INSERT"]


def test_clickhouse_detects_admin_rights():
    found = ch_parse([
        "GRANT SELECT ON *.* TO admin",
        "GRANT ALTER, DROP ON analytics.* TO admin",
        "GRANT SYSTEM ON *.* TO admin",
    ])
    assert set(found) == {"ALTER", "DROP", "SYSTEM"}


def test_clickhouse_detects_grant_option():
    found = ch_parse(["GRANT SELECT ON *.* TO lead WITH GRANT OPTION"])
    assert found == ["GRANT OPTION"]


def test_clickhouse_empty_grants():
    assert ch_parse([]) == []


# --- PostgreSQL -------------------------------------------------------------

def test_postgres_readonly_is_clean():
    from pii_scan.sources.postgres import parse_write_privileges as pg_parse

    rows = [("SELECT", "crm"), ("SELECT", "ops")]
    assert pg_parse(rows) == []


def test_postgres_detects_write():
    from pii_scan.sources.postgres import parse_write_privileges as pg_parse

    rows = [("SELECT", "crm"), ("INSERT", "crm"), ("UPDATE", "crm"),
            ("DELETE", "crm")]
    assert set(pg_parse(rows)) == {"INSERT", "UPDATE", "DELETE"}


def test_postgres_truncate_and_trigger_count_as_write():
    from pii_scan.sources.postgres import parse_write_privileges as pg_parse

    assert set(pg_parse([("TRUNCATE", "public"), ("TRIGGER", "public")])) == {
        "TRUNCATE", "TRIGGER"}
