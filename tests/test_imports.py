# -*- coding: utf-8 -*-
"""Каждый модуль пакета должен импортироваться.

Тест выглядит примитивным, но появился не зря: адаптеры MySQL и ClickHouse
подключаются лениво, внутри build_source, и в остальных тестах подменяются
заглушкой. Синтаксическая ошибка в них проходила весь набор тестов
незамеченной и всплывала только при реальном подключении к базе.
"""
from __future__ import annotations

import importlib
import pkgutil

import pytest

import pii_scan

MODULES = sorted(
    name for _, name, _ in pkgutil.walk_packages(
        pii_scan.__path__, prefix="pii_scan."
    )
)


def test_package_is_not_empty():
    assert len(MODULES) >= 10, f"найдено подозрительно мало модулей: {MODULES}"


@pytest.mark.parametrize("module", MODULES)
def test_module_imports(module):
    importlib.import_module(module)


def test_readonly_account_sql_is_valid_text():
    """SQL для администратора БД собирается без синтаксических сюрпризов."""
    from pii_scan.config import ScanOptions, SourceConfig
    from pii_scan.sources.clickhouse import ClickHouseSource
    from pii_scan.sources.mysql import MySQLSource

    options = ScanOptions()
    cases = [
        (MySQLSource(SourceConfig(name="m", type="mysql", host="h", port=3306,
                                  user="u"), options), "GRANT SELECT"),
        (ClickHouseSource(SourceConfig(name="c", type="clickhouse", host="h",
                                       port=9000, user="u"), options),
         "readonly = 2"),
    ]
    for source, expected in cases:
        sql = source.readonly_account_sql()
        assert expected in sql
        assert "pii_reader" in sql
        assert sql.count("\n") >= 2       # многострочный, а не склеенный
        assert "\\n" not in sql           # экранирование не просочилось


def test_access_report_contains_evidence():
    """В отчёте о блокировке должны быть и гранты, и SQL для DBA."""
    from pii_scan.config import ScanOptions, SourceConfig
    from pii_scan.sources.mysql import MySQLSource

    source = MySQLSource(
        SourceConfig(name="prod", type="mysql", host="10.0.0.1", port=3306,
                     user="app_rw"),
        ScanOptions(),
    )
    source.grants = ["GRANT SELECT, INSERT, UPDATE ON `crm`.* TO `app_rw`@`%`"]
    report = source._access_report(["INSERT", "UPDATE"])

    assert "app_rw" in report and "10.0.0.1:3306" in report
    assert "INSERT, UPDATE" in report
    assert "SHOW GRANTS" in report
    assert "GRANT SELECT, INSERT, UPDATE ON" in report   # сырое доказательство
    assert "CREATE USER 'pii_reader'" in report          # что просить у DBA
    assert "--allow-rw" in report


def test_documented_commands_parse():
    """Команды из README должны разбираться без ошибок.

    Документация уже расходилась с кодом: перечисляла ключи, которых нет,
    и категории, которые переименовали. Проверка дешёвая, поэтому пусть
    падает тест, а не пользователь.
    """
    from pii_scan.cli import build_parser

    parser = build_parser()
    for case in [
        "--dry-run --details",
        "--pause-ms 200 --max-minutes 120",
        "--detectors фио --only prod-mysql",
        "--detectors фио,контакты",
        "--detectors snils",
        "--list-detectors",
        "--limit 20000 --only prod-postgres --details",
        "--full-inventory --details",
        "--limit 100 --no-ner",
        "--strategy tail",
        "--formats xlsx",
        "--no-grouping",
        "--progress off --pause-ms 200 --max-minutes 120",
        "--max-qpm 60",
        "--out /srv/audit/2026-08",
        "--only prod-postgres --full-inventory --formats xlsx",
    ]:
        parser.parse_args(case.split())


def test_documented_categories_resolve():
    """Названия категорий из README должны существовать в каталоге."""
    from pii_scan.detectors import resolve_detectors

    for name in ["фио", "контакты", "документы", "финансы", "рождение",
                 "fio", "name", "contacts", "documents", "docs", "finance",
                 "birth", "snils", "bank_card"]:
        assert resolve_detectors([name]), f"категория {name} ничего не даёт"
