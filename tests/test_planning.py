# -*- coding: utf-8 -*-
"""Планирование обхода и ограничение нагрузки."""
from __future__ import annotations

import time

from pii_scan.config import ScanOptions, ThrottleOptions
from pii_scan.pacing import Pacer
from pii_scan.planning import build_plan, normalize_name
from pii_scan.sources.base import ColumnInfo, TableInfo


def cols(table: str, names) -> list:
    return [ColumnInfo(database="db", table=table, name=n) for n in names]


def make(tables_and_columns):
    tables, columns_map = [], {}
    for name, names, rows in tables_and_columns:
        tables.append(TableInfo(database="db", name=name, rows=rows))
        columns_map[f"db.{name}"] = cols(name, names)
    return tables, columns_map


# --- группировка ------------------------------------------------------------

def test_normalize_name():
    assert normalize_name("events_2026_08") == "events_#_#"
    assert normalize_name("orders_shard_063") == "orders_shard_#"
    assert normalize_name("clients") == "clients"


def test_partitioned_tables_are_grouped():
    """12 месячных таблиц — обследуются два образца, десять наследуют."""
    schema = ["id", "phone", "created_at"]
    tables, columns_map = make(
        [(f"events_2026_{m:02d}", schema, 1000 * m) for m in range(1, 13)]
    )
    plan = build_plan(tables, columns_map, group_min_size=4, group_samples=2)
    assert len(plan.to_scan) == 2
    assert len(plan.inferred_items) == 10
    # образцами выбраны самые крупные
    assert {i.table.name for i in plan.to_scan} == {"events_2026_12",
                                                    "events_2026_11"}


def test_different_structure_is_not_grouped():
    """Совпадения имени мало — структура должна быть той же."""
    tables, columns_map = make([
        ("log_1", ["id", "msg"], 10),
        ("log_2", ["id", "msg"], 10),
        ("log_3", ["id", "msg"], 10),
        ("log_4", ["id", "msg", "phone"], 10),   # другая структура
    ])
    plan = build_plan(tables, columns_map, group_min_size=4, group_samples=1)
    # трёх однотипных мало для группы из четырёх, четвёртая — сама по себе
    assert len(plan.to_scan) == 4


def test_grouping_can_be_disabled():
    schema = ["id", "phone"]
    tables, columns_map = make([(f"t_{i}", schema, 1) for i in range(10)])
    plan = build_plan(tables, columns_map, group_similar=False)
    assert len(plan.to_scan) == 10


# --- приоритет --------------------------------------------------------------

def test_suspicious_tables_go_first():
    """При нехватке времени сначала должно обследоваться вероятное."""
    tables, columns_map = make([
        ("metrics", ["ts", "value", "host"], 5_000_000),
        ("clients", ["snils", "phone", "last_name"], 100),
        ("cache", ["k", "v"], 10_000),
    ])
    plan = build_plan(tables, columns_map)
    assert plan.items[0].table.name == "clients"


# --- темп запросов ----------------------------------------------------------

def test_pacer_keeps_interval():
    pacer = Pacer(ThrottleOptions(pause_ms=120))
    start = time.monotonic()
    for _ in range(3):
        pacer.before_query()
    elapsed = time.monotonic() - start
    # первый запрос идёт сразу, между остальными — по паузе
    assert elapsed >= 0.2
    assert pacer.queries == 3


def test_queries_per_minute_sets_interval():
    pacer = Pacer(ThrottleOptions(max_queries_per_minute=30))
    assert abs(pacer.min_interval - 2.0) < 0.001


def test_time_budget_expires():
    pacer = Pacer(ThrottleOptions(max_duration_min=0))
    assert not pacer.expired()          # 0 = без ограничения
    pacer = Pacer(ThrottleOptions(max_duration_min=1))
    assert not pacer.expired()
    pacer._started -= 61
    assert pacer.expired()


# --- адаптивный размер выборки ---------------------------------------------

def test_wide_tables_read_fewer_rows():
    from pii_scan.sources.base import Source

    class Dummy(Source):
        type = "dummy"
        def connect(self): ...
        def close(self): ...
        def write_privileges(self): return []
        def list_tables(self): return []
        def list_columns(self, tables): return {}
        def sample(self, table, columns): ...
        def is_sampleable(self, data_type): return True

    from pii_scan.config import SourceConfig
    cfg = SourceConfig(name="d", type="mysql", host="h", port=1, user="u")
    source = Dummy(cfg, ScanOptions(sample_limit=500, max_value_len=512,
                                    max_bytes_per_table=2_000_000))
    assert source.effective_limit(cols("t", [f"c{i}" for i in range(10)])) == 500
    wide = source.effective_limit(cols("t", [f"c{i}" for i in range(400)]))
    assert wide < 500


def test_all_representatives_are_recorded():
    """Обследуются два образца — наследники должны получать находки обоих."""
    schema = ["id", "phone"]
    tables, columns_map = make([(f"part_{i:02d}", schema, 100 - i)
                                for i in range(6)])
    plan = build_plan(tables, columns_map, group_min_size=4, group_samples=2)
    leader = next(iter(plan.representatives))
    assert len(plan.representatives[leader]) == 2
    assert all(i.representative == leader for i in plan.inferred_items)


# --- стратегия выборки ------------------------------------------------------

def _dummy(strategy: str):
    from pii_scan.config import SourceConfig
    from pii_scan.sources.base import Source

    class Dummy(Source):
        type = "dummy"
        def connect(self): ...
        def close(self): ...
        def write_privileges(self): return []
        def list_tables(self): return []
        def list_columns(self, tables): return {}
        def sample(self, table, columns): ...
        def is_sampleable(self, data_type): return True

    cfg = SourceConfig(name="d", type="mysql", host="h", port=1, user="u")
    return Dummy(cfg, ScanOptions(sample_strategy=strategy))


def test_head_tail_splits_sample():
    """По умолчанию половина выборки читается с конца таблицы."""
    parts = _dummy("head_tail").sample_parts(500, has_order_key=True)
    assert parts == [(250, False), (250, True)]
    assert sum(p[0] for p in parts) == 500


def test_without_order_key_falls_back_to_head():
    """Без первичного ключа читать «с конца» нечем — берём голову."""
    assert _dummy("head_tail").sample_parts(500, has_order_key=False) == [
        (500, False)]


def test_explicit_strategies():
    assert _dummy("head").sample_parts(100, True) == [(100, False)]
    assert _dummy("tail").sample_parts(100, True) == [(100, True)]


# --- индикатор выполнения ---------------------------------------------------

def test_progress_bar_renders_and_counts():
    import io as _io
    from pii_scan.progress import ProgressBar, active

    stream = _io.StringIO()
    with ProgressBar(4, mode="on", title="src", stream=stream) as bar:
        assert active() is bar
        bar.advance("db.table_one", "осталось ~1 мин")
        assert bar.done == 1
        bar.advance("db.table_two")
    assert active() is None
    output = stream.getvalue()
    assert "src" in output and "1/4" in output and "2/4" in output
    assert "50%" in output


def test_progress_off_writes_nothing():
    import io as _io
    from pii_scan.progress import ProgressBar

    stream = _io.StringIO()
    with ProgressBar(10, mode="off", stream=stream) as bar:
        bar.advance("db.table")
    assert stream.getvalue() == ""


def test_progress_auto_is_disabled_without_terminal():
    import io as _io
    from pii_scan.progress import ProgressBar

    bar = ProgressBar(10, mode="auto", stream=_io.StringIO())
    assert not bar.enabled
