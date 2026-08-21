# -*- coding: utf-8 -*-
"""Оркестрация сканирования.

Сканер не знает ни SQL (это адаптеры в sources/), ни правил распознавания ПДн
(это detectors.py). Здесь только последовательность действий и подсчёт
уверенности.

Порядок работы по каждой таблице:
    1) детект по именам колонок и комментариям  — данные не читаются;
    2) одна выборка на таблицу (при --dry-run пропускается);
    3) детект по значениям + разбор JSON + NER по свободному тексту;
    4) скоринг.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from . import jsonwalk
from .config import AppConfig, ScanOptions
from .detectors import detect_in_column_name, detect_in_value, mask_value
from .model import ColumnRef, Finding, ScanResult, TableStat
from .nlp import NerTagger
from .sources.base import (
    ColumnInfo, ReadWriteAccessError, Sample, Source, SourceError, TableInfo,
    build_source,
)

log = logging.getLogger(__name__)


class Scanner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.options: ScanOptions = config.scan
        self.ner = NerTagger(enabled=self.options.ner and not self.options.dry_run)
        self.result = ScanResult()

    # --- точка входа ------------------------------------------------------

    def run(self) -> ScanResult:
        started = time.monotonic()
        self.result.started_at = datetime.now(timezone.utc).astimezone().isoformat(
            timespec="seconds")
        self.result.options = {
            "sample_limit": self.options.sample_limit,
            "dry_run": self.options.dry_run,
            "scan_json": self.options.scan_json,
            "ner": self.options.ner,
            "allow_rw": self.options.allow_rw,
        }

        for src_cfg in self.config.sources:
            try:
                self._scan_source(src_cfg)
            except ReadWriteAccessError:
                raise
            except SourceError as exc:
                self._error(f"[{src_cfg.name}] {exc}")
            except Exception as exc:  # noqa: BLE001 — один источник не роняет прогон
                self._error(f"[{src_cfg.name}] непредвиденная ошибка: {exc}")
                log.exception("ошибка при сканировании источника %s", src_cfg.name)

        self.result.finished_at = datetime.now(timezone.utc).astimezone().isoformat(
            timespec="seconds")
        self.result.duration_sec = round(time.monotonic() - started, 1)
        return self.result

    # --- источник ---------------------------------------------------------

    def _scan_source(self, src_cfg) -> None:
        source: Source = build_source(src_cfg, self.options)
        log.info("Источник '%s' (%s): подключение…", src_cfg.name, src_cfg.type)
        with source:
            privs = source.check_access()
            if privs:
                self._warn(
                    f"[{src_cfg.name}] учётная запись имеет права на запись "
                    f"({', '.join(privs)}), запуск разрешён флагом --allow-rw"
                )

            tables = source.filtered_tables()
            log.info("Источник '%s': к сканированию %d таблиц",
                     src_cfg.name, len(tables))
            self.result.sources.append({
                "name": src_cfg.name,
                "type": src_cfg.type,
                "host": f"{src_cfg.host}:{src_cfg.port}",
                "user": src_cfg.user,
                "tables": len(tables),
                "read_only": not privs,
            })

            columns_map = source.list_columns(tables)
            for i, table in enumerate(tables, 1):
                columns = columns_map.get(table.qualified, [])
                if not columns:
                    continue
                log.info("[%s] (%d/%d) %s — %d колонок",
                         src_cfg.name, i, len(tables), table.qualified, len(columns))
                try:
                    stat = self._scan_table(source, table, columns)
                except Exception as exc:  # noqa: BLE001
                    self._error(f"[{src_cfg.name}] {table.qualified}: {exc}")
                    continue
                if stat.findings:
                    self.result.tables.append(stat)

    # --- таблица ----------------------------------------------------------

    def _scan_table(self, source: Source, table: TableInfo,
                    columns: Sequence[ColumnInfo]) -> TableStat:
        stat = TableStat(
            source=source.name, database=table.database, table=table.name,
            rows_total=table.rows,
        )
        stat.columns_total = len(columns)

        findings: Dict[str, Finding] = {}
        for col in columns:
            finding = Finding(ref=ColumnRef(
                source=source.name, database=col.database, table=col.table,
                column=col.name, data_type=col.data_type, comment=col.comment,
            ), rows_total=table.rows)
            for code in detect_in_column_name(col.name, col.comment):
                finding.hit(code).by_name = True
            findings[col.name] = finding

        if not self.options.dry_run:
            sample = source.sample(table, columns)
            stat.rows_sampled = sample.rows_read
            self._analyze_sample(source, table, sample, findings)

        for finding in findings.values():
            finding.compute_scores()

        stat.findings = [f for f in findings.values() if f.hits]
        stat.findings.sort(key=lambda f: (-f.score, f.ref.full_column))
        return stat

    # --- разбор выборки ---------------------------------------------------

    def _analyze_sample(self, source: Source, table: TableInfo, sample: Sample,
                        findings: Dict[str, Finding]) -> None:
        for column, values in sample.values.items():
            finding = findings.get(column)
            if finding is None:
                continue
            finding.sampled = len(values)
            finding.non_null = len(values)
            ner_budget = self.options.ner_values_per_column
            json_paths: Dict[str, Finding] = {}

            for value in values:
                for code in detect_in_value(value):
                    hit = finding.hit(code)
                    hit.matched += 1
                    hit.add_example(self._example(value),
                                    self.options.examples_per_hit)

                if self.ner.available and ner_budget > 0 and \
                        self.ner.is_free_text(value):
                    ner_budget -= 1
                    for code in self.ner.analyze(value):
                        hit = finding.hit(code)
                        hit.matched += 1
                        hit.add_example(self._example(value),
                                        self.options.examples_per_hit)

                if self.options.scan_json:
                    self._analyze_json(source, table, finding, value, json_paths)

            for virtual in json_paths.values():
                virtual.compute_scores()
                findings[virtual.ref.full_column] = virtual

    def _analyze_json(self, source: Source, table: TableInfo, parent: Finding,
                      value: str, json_paths: Dict[str, Finding]) -> None:
        """ПДн внутри payload: каждый ключ становится виртуальной колонкой."""
        data = jsonwalk.parse(value)
        if data is None:
            return
        for path, leaf in jsonwalk.walk(data):
            if path not in json_paths:
                if len(json_paths) >= self.options.max_json_paths:
                    return
                ref = ColumnRef(
                    source=source.name, database=parent.ref.database,
                    table=parent.ref.table, column=parent.ref.column,
                    data_type=parent.ref.data_type, comment=parent.ref.comment,
                    json_path=path,
                )
                virtual = Finding(ref=ref, rows_total=parent.rows_total)
                for code in detect_in_column_name(jsonwalk.leaf_name(path)):
                    virtual.hit(code).by_name = True
                json_paths[path] = virtual
            virtual = json_paths[path]
            virtual.non_null += 1
            virtual.sampled += 1
            for code in detect_in_value(leaf):
                hit = virtual.hit(code)
                hit.matched += 1
                hit.add_example(self._example(leaf), self.options.examples_per_hit)

    # --- мелочи -----------------------------------------------------------

    def _example(self, value: str) -> str:
        return value[:64] if self.options.show_values else mask_value(value)

    def _warn(self, message: str) -> None:
        log.warning(message)
        self.result.warnings.append(message)

    def _error(self, message: str) -> None:
        log.error(message)
        self.result.errors.append(message)


def scan(config: AppConfig) -> ScanResult:
    return Scanner(config).run()
