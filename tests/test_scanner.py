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
        # Имя ни о чём не говорит, комментария нет — найтись должно
        # исключительно по содержимому.
        ("field_23", "varchar", ""),
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
    "field_23": ["I10", "E11.9", "J06.9"],
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

    # Слабый сигнал: одно попадание на большой выборке. Считаем вручную —
    # в фикстуре всего три строки, а на трёх значениях доля не бывает низкой.
    from pii_scan.model import ColumnRef, Finding
    faint = Finding(ref=ColumnRef("s", "d", "t", "comment"), non_null=500,
                    sampled=500)
    faint.hit("inn").matched = 1
    faint.compute_scores()
    assert faint.verdict == "no"
    assert any("ИНН" in weak for weak in faint.weak_titles)

    clean = found["id"]
    assert clean.verdict == "no"
    assert clean.summary_kind == "—"


# --- выбор категорий ПДн ----------------------------------------------------

def test_only_fio_is_searched(monkeypatch, app_config):
    """При выборе одной категории остальные правила не срабатывают."""
    app_config.scan.detectors = ["names"]
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}

    assert found["last_name"].verdict == "pii"          # ФИО ищем
    assert "contact" not in found                       # почту — нет
    assert "diagnosis" not in found                     # спецкатегории — нет

    # ни одно правило вне выбранной категории не сработало
    fired = {code for f in result.tables[0].findings for code in f.scores}
    assert fired <= {"fio", "name_part", "ner_person"}
    assert found["f_17"].verdict != "pii"               # СНИЛС не засчитан
    assert result.options["detectors_limited"] is True
    # в конфиге латиница, в отчёте — русское название
    assert result.options["detectors"] == "ФИО"


def test_cyrillic_alias_still_works(monkeypatch, app_config):
    """Конфиги, написанные до перехода на латиницу, не должны ломаться."""
    app_config.scan.detectors = ["контакты"]
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}
    assert found["contact"].verdict == "pii"            # email
    assert "last_name" not in found


def test_latin_and_cyrillic_are_equivalent():
    """Русское название и латинское должны давать один и тот же набор."""
    from pii_scan.detectors import resolve_detectors

    for latin, cyrillic in [("names", "фио"), ("contacts", "контакты"),
                            ("documents", "документы"), ("finance", "финансы"),
                            ("birth", "рождение"), ("special", "спецкатегории"),
                            ("relatives", "родственники")]:
        assert resolve_detectors([latin]) == resolve_detectors([cyrillic]), latin


def test_single_code_can_be_selected(monkeypatch, app_config):
    """Кроме групп принимается и отдельный код детектора."""
    app_config.scan.detectors = ["snils"]
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}
    assert found["f_17"].verdict == "pii"
    assert set(found) == {"f_17"}


def test_all_categories_by_default(monkeypatch, app_config):
    result = run(monkeypatch, app_config)
    assert result.options["detectors"] == "все категории"
    assert result.options["detectors_limited"] is False


def test_unknown_category_is_rejected():
    from pii_scan.detectors import resolve_detectors
    with pytest.raises(ValueError, match="неизвестные категории"):
        resolve_detectors(["фамилии"])


def test_filter_narrows_rules_not_columns(monkeypatch, app_config):
    """Выбор категорий не сужает охват чтения.

    Ограничение --detectors выводит из работы правила, но не колонки:
    значения читаются у всех полей, иначе имя колонки снова начало бы
    решать, что проверять.
    """
    app_config.scan.detectors = ["фио"]
    app_config.scan.full_inventory = True
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for f in result.tables[0].findings}

    # колонка с почтой прочитана, хотя правило про почту выключено
    assert found["contact"].non_null == 3
    assert found["contact"].verdict == "no"
    assert "email" not in found["contact"].scores

    # и колонка с техническими числами тоже прочитана
    assert found["order_total"].non_null == 3


def test_opaque_column_found_by_values_alone(monkeypatch, app_config):
    """`field_23` с кодами МКБ-10: ни имени, ни комментария — только значения.

    Закрепляет требование «имя поля не участвует в отсеве»: колонка,
    о которой схема не говорит ничего, обследуется наравне с остальными.
    """
    result = run(monkeypatch, app_config)
    found = {f.ref.column: f for f in result.tables[0].findings}
    assert "field_23" in found
    hit = found["field_23"].hits["health"]
    assert not hit.by_name          # имя не дало ни одного очка
    assert hit.matched == 3         # вывод целиком построен на значениях


def test_score_follows_share_of_matched_values():
    """Единичное попадание и сплошная колонка не должны весить одинаково.

    Одно значение из пятисот — скорее опечатка в чужом поле; 485 из 500 —
    поле для того и заведено. Между ними должна быть не разница в оттенке,
    а разные вердикты.
    """
    from pii_scan.model import ColumnRef, Finding

    def verdict(matched):
        f = Finding(ref=ColumnRef("s", "d", "t", "c"), non_null=500,
                    sampled=500)
        f.hit("snils").matched = matched
        f.compute_scores()
        return f.verdict, f.score

    assert verdict(1)[0] == "no"        # опечатка в чужом поле
    assert verdict(50)[0] == "no"       # примесь: 10 % значений
    assert verdict(100)[0] == "maybe"   # пятая часть колонки — уже вопрос
    assert verdict(250)[0] == "pii"     # половина — шкала насыщается
    assert verdict(485)[0] == "pii"
    # оценка растёт монотонно вместе с долей и упирается в потолок
    scores = [verdict(m)[1] for m in (1, 50, 100, 250, 485, 500)]
    assert scores == sorted(scores)
    assert scores[-1] == scores[-2] == 1.0      # после половины — насыщение
    assert len(set(scores[:4])) == 4            # до неё разрешение сохраняется


def test_weak_signal_shows_count_not_percent():
    """У одного попадания из пятисот процент вырождается в «0%»."""
    from pii_scan.model import ColumnRef, Finding

    f = Finding(ref=ColumnRef("s", "d", "t", "c"), non_null=500)
    f.hit("snils").matched = 1
    f.compute_scores()
    assert f.verdict == "no"                     # колонкой с ПДн не считаем
    assert "1 из 500" in f.summary_kind          # но и не умалчиваем


def test_review_bucket_splits_by_basis(monkeypatch, app_config):
    """«Требует проверки» — это две разные работы, а не одна куча.

    Поле, где сработало содержимое, разбирают глазами. Поле, которое
    держится на одном своём названии, разбирают вопросом к разработчикам.
    """
    from pii_scan.model import ColumnRef, Finding, ScanResult, TableStat

    by_values = Finding(ref=ColumnRef("s", "d", "t1", "c"), non_null=500)
    by_values.hit("passport_rf").matched = 500
    by_values.compute_scores()

    by_name = Finding(ref=ColumnRef("s", "d", "t2", "passport_seria"),
                      non_null=500)
    by_name.hit("passport_rf").by_name = True
    by_name.compute_scores()

    assert by_values.verdict == by_name.verdict == "maybe"
    assert by_values.confirmed_by_values
    assert not by_name.confirmed_by_values

    result = ScanResult()
    for finding in (by_values, by_name):
        stat = TableStat(source="s", database="d",
                         table=finding.ref.table, rows_total=500)
        stat.findings = [finding]
        result.tables.append(stat)

    assert len(result.pending_findings) == 2
    assert [f.ref.table for f in result.pending_confirmed] == ["t1"]
    assert [f.ref.table for f in result.pending_by_name] == ["t2"]
    # подтверждённое содержимым идёт первым — с него начинают разбор
    assert result.pending_findings[0].ref.table == "t1"


def test_pending_field_inside_pii_table_is_counted():
    """Поле на разбор не должно теряться из-за соседей по таблице.

    `maybe_tables` — это таблицы, о которых не известно вообще ничего. Если
    считать разбор по ним, то `passport_seria` в таблице, где ФИО уже
    нашлись, в сводку не попадёт: таблица-то давно «с ПДн». Разбирать поле
    от этого не перестанут.
    """
    from pii_scan.model import ColumnRef, Finding, ScanResult, TableStat

    confident = Finding(ref=ColumnRef("s", "d", "clients", "fio"), non_null=500)
    confident.hit("fio").matched = 500
    confident.compute_scores()

    pending = Finding(ref=ColumnRef("s", "d", "clients", "passport_seria"),
                      non_null=500)
    pending.hit("passport_rf").by_name = True
    pending.compute_scores()

    stat = TableStat(source="s", database="d", table="clients", rows_total=500)
    stat.findings = [confident, pending]
    result = ScanResult()
    result.tables.append(stat)

    assert result.maybe_tables == []            # таблица уже числится с ПДн
    assert len(result.pending_findings) == 1    # а поле всё равно на разборе
    assert result.pending_by_name[0].ref.column == "passport_seria"


def test_examples_are_off_by_default(monkeypatch, app_config):
    """Маска оставляет длину, формат и первые символы — это тоже утечка.

    Отчёт уходит разработчикам и внешним проверяющим, поэтому примеры
    значений включаются осознанно, а не достаются по умолчанию.
    """
    from pii_scan.config import ScanOptions
    from pii_scan.report.markdown import render_detailed

    assert ScanOptions().examples_per_hit == 0

    result = run(monkeypatch, app_config)
    assert all(not hit.examples
               for f in result.all_findings for hit in f.hits.values())
    report = render_detailed(result)
    assert "Примеры (маск.)" not in report          # столбца в таблицах нет
    assert "включаются ключом `--examples`" in report  # но умолчание названо


def test_examples_appear_when_asked(monkeypatch, app_config):
    from pii_scan.report.markdown import render_detailed

    app_config.scan.examples_per_hit = 2
    result = run(monkeypatch, app_config)
    collected = [hit.examples
                 for f in result.all_findings for hit in f.hits.values()]
    assert any(collected)
    assert all(len(ex) <= 2 for ex in collected)
    assert "Примеры (маск.)" in render_detailed(result)


def test_basis_names_the_unconfirmed_case(monkeypatch, app_config):
    """«имя поля» и «только имя поля» — разница, которую надо видеть."""
    from pii_scan.model import ColumnRef, Finding

    only_name = Finding(ref=ColumnRef("s", "d", "t", "passport_seria"),
                        non_null=500)
    only_name.hit("passport_rf").by_name = True
    only_name.compute_scores()
    assert only_name.basis == "только имя поля"

    both = Finding(ref=ColumnRef("s", "d", "t", "snils"), non_null=500)
    hit = both.hit("snils")
    hit.by_name, hit.matched = True, 500
    both.compute_scores()
    assert both.basis == "имя поля, значения"


def test_placeholders_leave_the_denominator():
    """Колонка телефонов, наполовину состоящая из «н/д», — колонка телефонов.

    Заглушка это записанное отсутствие значения. Считая её доводом против,
    сканер занижал долю ровно на степень незаполненности поля.
    """
    from pii_scan.model import ColumnRef, Finding

    # 319 телефонов, 360 заглушек — случай с боевой базы
    f = Finding(ref=ColumnRef("s", "d", "t", "number_b"), sampled=679,
                non_null=319, placeholders=360)
    f.hit("phone").matched = 319
    f.compute_scores()
    assert f.verdict == "pii"
    assert f.coverage == "319/319"


def test_placeholders_cannot_manufacture_certainty():
    """Одно попадание среди пятисот «н/д» — не колонка ПДн.

    Без ограничения снизу очистка знаменателя дала бы 1/1 = 100 %.
    """
    from pii_scan.model import ColumnRef, Finding

    f = Finding(ref=ColumnRef("s", "d", "t", "junk"), sampled=500,
                non_null=1, placeholders=499)
    f.hit("phone").matched = 1
    f.compute_scores()
    assert f.verdict == "no"


def test_format_only_rules_stay_capped_by_weight():
    """Ловушка: колонка случайных 10-значных чисел.

    Формат паспорта совпадает у всех значений, но контрольной суммы у
    правила нет — насыщение шкалы не должно поднимать такую колонку выше
    «требует проверки». От неё защищает вес правила, а не доля.
    """
    from pii_scan.model import ColumnRef, Finding

    f = Finding(ref=ColumnRef("s", "d", "t", "random_ids"), sampled=679,
                non_null=679)
    f.hit("passport_rf").matched = 679
    f.compute_scores()
    assert f.verdict == "maybe"
    assert f.score < 0.70


# --- упрощённый отчёт -------------------------------------------------------

def test_confirmed_only_drops_name_based_findings(monkeypatch, app_config):
    """Упрощённый отчёт: без полей, чей вывод держится на одном названии."""
    app_config.scan.confirmed_only = True
    result = run(monkeypatch, app_config)
    reported = {f.ref.full_column for t in result.tables for f in t.findings}

    # diagnosis и emergency_contact опознаются по имени — их не остаётся
    assert "diagnosis" not in reported
    # last_name подтверждён значениями — остаётся
    assert "last_name" in reported
    assert all(f.confirmed_by_values for t in result.tables for f in t.findings)

    # исключённое объявлено, а не пропало молча
    assert result.options["excluded_by_filter"] > 0
    assert any("--confirmed-only" in w for w in result.warnings)


def test_confirmed_only_keeps_excluded_visible_in_inventory(monkeypatch,
                                                            app_config):
    """Полная опись — доказательство охвата, отсеянное в ней видно."""
    app_config.scan.confirmed_only = True
    app_config.scan.full_inventory = True
    result = run(monkeypatch, app_config)
    found = {f.ref.full_column: f for t in result.tables for f in t.findings}

    assert "исключено фильтром" in found["diagnosis"].summary_kind


def test_name_boost_is_configurable(monkeypatch, app_config):
    """Коэффициент настраивается — но делает не то, что ждут от фильтра."""
    from pii_scan.model import ColumnRef, Finding

    def score(boost):
        f = Finding(ref=ColumnRef("s", "d", "t", "c"), sampled=500, non_null=500)
        f.hit("passport_rf").by_name = True
        f.compute_scores(boost)
        return f.score

    assert score(0.35) == 0.35
    assert score(0.20) == 0.20

    # А вот правило, где имя решает само, коэффициенту не подчиняется —
    # ровно поэтому для упрощённого отчёта нужен confirmed_only
    conclusive = Finding(ref=ColumnRef("s", "d", "t", "diagnosis"),
                         sampled=500, non_null=500)
    conclusive.hit("health").by_name = True
    conclusive.compute_scores(0.0)
    assert conclusive.verdict == "pii"
