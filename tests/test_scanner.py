# -*- coding: utf-8 -*-
"""Сквозной прогон сканера на поддельном источнике — без реальной БД."""
from __future__ import annotations

from typing import Dict, List, Sequence

import pytest

from pii_scan import scanner as scanner_module
from pii_scan.config import AppConfig, ScanOptions, SourceConfig
from pii_scan.scanner import Scanner
from pii_scan.sources.base import ColumnInfo, ReadWriteAccessError, Sample, Source, TableInfo

TABLES = {
    "shop.clients": [
        ("id", "int", ""),
        ("last_name", "varchar", ""),
        ("contact", "varchar", ""),
        ("f_17", "varchar", "СНИЛС сотрудника"),
        ("order_total", "decimal", ""),
        ("ext_code", "varchar", ""),
        ("payload", "json", ""),
        ("city", "varchar", ""),
        ("emergency_contact", "varchar", ""),
        ("diagnosis", "varchar", ""),
    ]
}

ROWS = {
    "id": ["1", "2", "3"],
    "last_name": ["Иванов", "Петрова", "Кузнецов"],
    "contact": ["ivanov@example.com", "petrova@example.com", "kuz@example.com"],
    "f_17": ["112-233-445 95", "112-233-445 95", "112-233-445 95"],
    "order_total": ["1500.00", "230.50", "9999.99"],
    # 9876543210 случайно проходит контроль ИНН, остальные — нет
    "ext_code": ["9876543210", "1234567890", "1122334455"],
    "payload": [
        '{"client": {"phone": "+79161234567"}, "note": "доставка"}',
        '{"client": {"phone": "+79161234568"}, "note": "самовывоз"}',
        '{"client": {"phone": "+79161234569"}, "note": "срочно"}',
    ],
    "city": ["Челябинск", "Самара", "Казань"],
    "emergency_contact": ["Иванова Мария Петровна", "—", "—"],
    "diagnosis": ["ОРВИ", "", ""],
}


class FakeSource(Source):
    type = "fake"

    def __init__(self, config, options, write_privs=None):
        super().__init__(config, options)
        self._privs = write_privs or []

    def connect(self):
        self._conn = object()

    def close(self):
        self._conn = None

    def write_privileges(self) -> List[str]:
        return self._privs

    def list_tables(self) -> List[TableInfo]:
        return [TableInfo(database="shop", name="clients", rows=1000)]

    def list_columns(self, tables: Sequence[TableInfo]) -> Dict[str, List[ColumnInfo]]:
        return {
            "shop.clients": [
                ColumnInfo(database="shop", table="clients", name=name,
                           data_type=dtype, comment=comment)
                for name, dtype, comment in TABLES["shop.clients"]
            ]
        }

    def is_sampleable(self, data_type: str) -> bool:
        return True

    def sample(self, table: TableInfo, columns: Sequence[ColumnInfo]) -> Sample:
        values = {c.name: [v for v in ROWS[c.name] if v] for c in columns}
        return Sample(values=values, rows_read=3)


@pytest.fixture
def app_config():
    return AppConfig(
        scan=ScanOptions(ner=False, sample_limit=10),
        sources=[SourceConfig(name="fake", type="mysql", host="h", port=1,
                              user="u", password="")],
    )


def run(monkeypatch, app_config, write_privs=None):
    monkeypatch.setattr(
        scanner_module, "build_source",
        lambda cfg, opts, pacer=None: FakeSource(cfg, opts, write_privs),
    )
    return Scanner(app_config).run()


def test_finds_expected_columns(monkeypatch, app_config):
    result = run(monkeypatch, app_config)
    assert len(result.tables) == 1
    table = result.tables[0]
    found = {f.ref.full_column: f for f in table.findings}

    assert found["contact"].verdict == "pii"
    assert "email" in found["contact"].codes
    # имя колонки f_17 бессмысленное, но сработали комментарий и значения
    assert found["f_17"].hits["snils"].by_name is True
    assert found["f_17"].hits["snils"].matched == 3
    assert found["f_17"].verdict == "pii"
    assert found["last_name"].verdict == "pii"


def test_json_paths_become_virtual_columns(monkeypatch, app_config):
    result = run(monkeypatch, app_config)
    columns = {f.ref.full_column for f in result.tables[0].findings}
    assert "payload::$.client.phone" in columns


def test_technical_columns_are_clean(monkeypatch, app_config):
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}
    assert "order_total" not in found or found["order_total"].verdict == "no"
    assert "id" not in found or found["id"].verdict == "no"


def test_sequential_codes_are_not_pii(monkeypatch, app_config):
    """Технические коды не объявляются ПДн, но и не замалчиваются.

    Формат без контрольной суммы (10 цифр — как у паспорта) выносится на
    ручную проверку: молчать нельзя, объявлять ПДн — тоже.
    """
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}
    code = found["ext_code"]
    assert code.verdict == "maybe"
    assert code.score < 0.7


def test_name_only_raises_confidence_not_gates_it(monkeypatch, app_config):
    """Имя поля усиливает вывод, но без него значения не отбрасываются.

    Те же самые значения: в колонке с говорящим именем — уверенная находка,
    в колонке с невнятным — «требует проверки». Молчать нельзя ни в одном
    из случаев, иначе ПДн в поле вроде rp_responsible теряются.
    """
    monkeypatch.setitem(ROWS, "passport_serial", list(ROWS["ext_code"]))
    monkeypatch.setitem(
        TABLES, "shop.clients",
        TABLES["shop.clients"] + [("passport_serial", "varchar", "")],
    )
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}

    assert found["passport_serial"].verdict == "pii"
    assert "passport_rf" in found["passport_serial"].codes
    # то же содержимое без подсказки в имени — не молчание, а проверка
    assert found["ext_code"].verdict == "maybe"
    assert "passport_rf" in found["ext_code"].codes


def test_lone_surnames_are_found(monkeypatch, app_config):
    """Колонка из одних фамилий не теряется, даже если имя поля ни о чём.

    Ровно этот случай пропускался на боевой базе: поле rp_responsible,
    в каждой строке одна фамилия.
    """
    monkeypatch.setitem(ROWS, "rp_responsible",
                        ["Иванов", "Кузнецова", "Соколов"])
    monkeypatch.setitem(
        TABLES, "shop.clients",
        TABLES["shop.clients"] + [("rp_responsible", "varchar", "")],
    )
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}
    assert found["rp_responsible"].verdict in ("pii", "maybe")
    assert "name_part" in found["rp_responsible"].codes


def test_city_column_is_flagged_for_review_not_as_pii(monkeypatch, app_config):
    """Города неотличимы от фамилий по значению — но и молчать о них нельзя.

    Ростов, Псков, Киров выглядят как фамилии. Такая колонка выносится на
    ручную проверку, а не объявляется ПДн и не выбрасывается молча.
    """
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}
    city = found["city"]
    assert city.verdict == "maybe"
    assert city.score < 0.7


def test_special_and_third_party_flags(monkeypatch, app_config):
    result = run(monkeypatch, app_config)
    table = result.tables[0]
    assert table.has_special           # diagnosis — по имени колонки
    assert table.third_party           # emergency_contact


def test_dry_run_reads_no_values(monkeypatch, app_config):
    app_config.scan.dry_run = True
    result = run(monkeypatch, app_config)
    table = result.tables[0]
    assert table.rows_sampled == 0
    assert all(f.non_null == 0 for f in table.findings)
    # по именам колонок находки всё равно есть
    assert {f.ref.column for f in table.findings} >= {"last_name", "diagnosis"}
    # «не читали данные» не то же самое, что «колонка пуста»: спецкатегории
    # в сухом прогоне должны оставаться уверенной находкой
    found = {f.ref.column: f for f in table.findings}
    assert found["diagnosis"].verdict == "pii"
    assert found["emergency_contact"].verdict == "pii"


def test_write_access_blocks_scan(monkeypatch, app_config):
    with pytest.raises(ReadWriteAccessError):
        run(monkeypatch, app_config, write_privs=["INSERT", "DROP"])


def test_allow_rw_permits_scan(monkeypatch, app_config):
    app_config.scan.allow_rw = True
    result = run(monkeypatch, app_config, write_privs=["INSERT"])
    assert result.warnings
    assert result.tables


def test_ner_budget_is_spread_over_whole_sample(monkeypatch, app_config):
    """Бюджет NER не должен целиком уходить на начало выборки."""
    app_config.scan.ner = True
    app_config.scan.ner_values_per_column = 4
    from pii_scan.scanner import Scanner

    seen = []

    class FakeNer:
        available = True
        @staticmethod
        def is_free_text(value):
            return True
        def analyze(self, text):
            seen.append(text)
            return set()

    monkeypatch.setattr(
        scanner_module, "build_source",
        lambda cfg, opts, pacer=None: FakeSource(cfg, opts, None),
    )
    scanner = Scanner(app_config)
    scanner.ner = FakeNer()
    values = [f"значение номер {i}" for i in range(100)]
    targets = scanner._ner_targets(values)
    assert len(targets) == 4
    # берутся из разных частей выборки, а не первые четыре подряд
    assert max(targets) >= 50


def test_details_output_lists_fields(monkeypatch, app_config):
    """Разбивка по полям — то, что отдают разработчикам на проверку."""
    from pii_scan.report.console import render_details

    result = run(monkeypatch, app_config)
    text = render_details(result)

    # поле, вид ПДн, основание вывода и таблица — всё в одном месте
    assert "shop.clients" in text
    assert "contact" in text and "адрес электронной почты" in text
    assert "f_17" in text and "СНИЛС" in text
    assert "payload::$.client.phone" in text        # и ключи внутри JSON
    assert "имя поля" in text or "значения" in text
    # чистые колонки в детализацию не попадают
    assert "order_total" not in text


def test_details_empty_without_findings(monkeypatch, app_config):
    from pii_scan.report.console import render_details
    from pii_scan.model import ScanResult

    assert render_details(ScanResult()) == ""


def test_full_inventory_lists_every_field(monkeypatch, app_config):
    """Опись должна включать и чистые поля — это доказательство охвата."""
    app_config.scan.full_inventory = True
    result = run(monkeypatch, app_config)
    table = result.tables[0]

    columns = {f.ref.column for f in table.findings}
    # технические поля без ПДн тоже перечислены
    assert {"id", "order_total", "ext_code"} <= columns
    assert len(columns) >= len(TABLES["shop.clients"])

    clean = next(f for f in table.findings if f.ref.column == "id")
    assert clean.verdict == "no"
    assert clean.summary_kind in ("—",) or "слабый признак" in clean.summary_kind


def test_full_inventory_off_by_default(monkeypatch, app_config):
    result = run(monkeypatch, app_config)
    columns = {f.ref.column for f in result.tables[0].findings}
    assert "id" not in columns


def test_weak_signal_is_shown_in_inventory(monkeypatch, app_config):
    """Совпадение ниже порога не выбрасывается молча, а помечается слабым."""
    app_config.scan.full_inventory = True
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}

    code = found["ext_code"]
    # ИНН подтвердился лишь в одном значении из трёх — это ниже порога,
    # но в описи такой сигнал должен остаться видимым
    assert any("ИНН" in weak for weak in code.weak_titles)

    clean = found["id"]
    assert clean.verdict == "no"
    assert clean.summary_kind == "—"
