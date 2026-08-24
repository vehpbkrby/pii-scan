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
from copy import deepcopy
from dataclasses import replace
from typing import Dict, List, Optional, Sequence

from . import jsonwalk
from .config import AppConfig, ScanOptions
from .detectors import (
    NER_CODES, detect_in_column_name, detect_in_value, mask_value,
)
from .model import ColumnRef, Finding, ScanResult, TableStat
from .nlp import NerTagger
from .pacing import Pacer
from .planning import Plan, build_plan
from .progress import ProgressBar
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
        self.pacer = Pacer(config.throttle)
        self.result = ScanResult()

    # --- точка входа ------------------------------------------------------

    def run(self) -> ScanResult:
        started = time.monotonic()
        self.result.started_at = datetime.now(timezone.utc).astimezone().isoformat(
            timespec="seconds")
        self.result.options = {
            "sample_limit": self.options.sample_limit,
            "sample_strategy": self.options.sample_strategy,
            "full_inventory": self.options.full_inventory,
            "dry_run": self.options.dry_run,
            "scan_json": self.options.scan_json,
            "ner": self.options.ner,
            "allow_rw": self.options.allow_rw,
            "pause_ms": self.config.throttle.pause_ms,
            "max_queries_per_minute": self.config.throttle.max_queries_per_minute,
            "max_duration_min": self.config.throttle.max_duration_min,
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
        source: Source = build_source(src_cfg, self.options, self.pacer)
        log.info("Источник '%s' (%s): подключение…", src_cfg.name, src_cfg.type)
        with source:
            privs = source.check_access()
            if privs:
                self._warn(
                    f"[{src_cfg.name}] учётная запись имеет права на запись "
                    f"({', '.join(privs)}), запуск разрешён флагом --allow-rw"
                )

            tables = source.filtered_tables()
            columns_map = source.list_columns(tables)
            plan = build_plan(
                tables, columns_map,
                group_similar=self.options.group_similar_tables,
                group_min_size=self.options.group_min_size,
                group_samples=self.options.group_samples,
            )
            targets = plan.to_scan
            log.info("Источник '%s': таблиц %d, к обследованию %d%s",
                     src_cfg.name, len(tables), len(targets),
                     f", по образцу {len(plan.inferred_items)}"
                     if plan.inferred_items else "")
            if plan.groups:
                self._note_groups(src_cfg.name, plan)

            self.result.sources.append({
                "name": src_cfg.name,
                "type": src_cfg.type,
                "host": f"{src_cfg.host}:{src_cfg.port}",
                "user": src_cfg.user,
                "tables": len(tables),
                "scanned": len(targets),
                "inferred": len(plan.inferred_items),
                "read_only": not privs,
            })

            scanned: Dict[str, TableStat] = {}
            with ProgressBar(len(targets), mode=self.options.progress,
                             title=src_cfg.name) as bar:
                for i, item in enumerate(targets, 1):
                    if self.pacer.expired():
                        self._warn(
                            f"[{src_cfg.name}] прогон остановлен по бюджету "
                            f"времени: обследовано {i - 1} таблиц из "
                            f"{len(targets)}. Увеличьте "
                            f"throttle.max_duration_min или сузьте охват."
                        )
                        break
                    self._progress(bar, src_cfg.name, i, len(targets),
                                   item.table)
                    try:
                        stat = self._scan_table(source, item.table, item.columns)
                    except Exception as exc:  # noqa: BLE001
                        self._error(
                            f"[{src_cfg.name}] {item.table.qualified}: {exc}")
                        continue
                    scanned[item.table.qualified] = stat
                    if stat.findings:
                        self.result.tables.append(stat)

            for item in plan.inferred_items:
                origins = [
                    scanned[q]
                    for q in plan.representatives.get(item.representative,
                                                      [item.representative])
                    if q in scanned and scanned[q].findings
                ]
                if not origins:
                    continue
                self.result.tables.append(self._inherit(item, origins))

            for message in source.warnings:
                if message not in self.result.warnings:
                    self.result.warnings.append(message)
            log.info("Источник '%s' обследован (%s)",
                     src_cfg.name, self.pacer.summary())

    def _note_groups(self, source_name: str, plan: Plan) -> None:
        total = sum(len(members) for members in plan.groups.values())
        message = (
            f"[{source_name}] однотипных таблиц: {total} в "
            f"{len(plan.groups)} группах — обследованы образцы, остальные "
            f"наследуют результат (см. пометку «по образцу» в отчёте)"
        )
        log.info(message)
        self.result.warnings.append(message)

    def _inherit(self, item, origins: List[TableStat]) -> TableStat:
        """Переносит на однотипную таблицу объединённые находки образцов.

        Образцов может быть несколько: в одной месячной партиции поле бывает
        заполнено, а в другой пусто, — берём лучшее свидетельство по каждому
        полю, иначе второй обследованный образец не давал бы ничего.
        """
        stat = TableStat(
            source=origins[0].source, database=item.table.database,
            table=item.table.display_name, rows_total=item.table.rows,
            columns_total=len(item.columns),
            inferred_from=item.representative,
        )
        best: Dict[str, Finding] = {}
        for origin in origins:
            for source_finding in origin.findings:
                key = source_finding.ref.full_column
                current = best.get(key)
                if current is None or source_finding.score > current.score:
                    best[key] = source_finding

        for source_finding in best.values():
            ref = replace(source_finding.ref, table=item.table.name,
                          database=item.table.database)
            clone = Finding(
                ref=ref, rows_total=item.table.rows,
                sampled=source_finding.sampled, non_null=source_finding.non_null,
                hits=deepcopy(source_finding.hits),
                inferred_from=item.representative,
            )
            clone.compute_scores()
            stat.findings.append(clone)
        stat.findings.sort(key=lambda f: (-f.score, f.ref.full_column))
        return stat

    def _progress(self, bar: ProgressBar, source_name: str, done: int,
                  total: int, table: TableInfo) -> None:
        eta = self.pacer.eta(done - 1, total)
        if bar.enabled:
            bar.advance(table.qualified, eta)
            return
        # Без терминала (cron, systemd, docker без -t) полоса бессмысленна:
        # пишем в журнал редкие отметки вместо тысячи строк
        step = max(1, total // 20)
        if done == 1 or done == total or done % step == 0:
            log.info("[%s] %d/%d (%d%%)%s", source_name, done, total,
                     done * 100 // total, f" — {eta}" if eta else "")
        else:
            log.debug("[%s] (%d/%d) %s", source_name, done, total,
                      table.qualified)

    # --- таблица ----------------------------------------------------------

    def _scan_table(self, source: Source, table: TableInfo,
                    columns: Sequence[ColumnInfo]) -> TableStat:
        stat = TableStat(
            source=source.name, database=table.database,
            table=table.display_name, rows_total=table.rows,
        )
        stat.columns_total = len(columns)

        findings: Dict[str, Finding] = {}
        for col in columns:
            finding = Finding(ref=ColumnRef(
                source=source.name, database=col.database, table=col.table,
                column=col.name, data_type=col.data_type, comment=col.comment,
            ), rows_total=table.rows, dry_run=self.options.dry_run)
            for code in detect_in_column_name(col.name, col.comment):
                finding.hit(code).by_name = True
            findings[col.name] = finding

        if not self.options.dry_run:
            sample = source.sample(table, columns)
            stat.rows_sampled = sample.rows_read
            self._analyze_sample(source, table, sample, findings)

        for finding in findings.values():
            finding.compute_scores()

        # В режиме полной описи в отчёт идут все поля, включая чистые: это
        # доказательство, что проверено всё, а не выборочно.
        stat.findings = [
            f for f in findings.values()
            if f.hits or self.options.full_inventory
        ]
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
            ner_targets = self._ner_targets(values)
            ner_examined = 0
            json_paths: Dict[str, Finding] = {}

            for position, value in enumerate(values):
                for code in detect_in_value(value):
                    hit = finding.hit(code)
                    hit.matched += 1
                    hit.add_example(self._example(value),
                                    self.options.examples_per_hit)

                if position in ner_targets:
                    ner_examined += 1
                    for code in self.ner.analyze(value):
                        hit = finding.hit(code)
                        hit.matched += 1
                        hit.add_example(self._example(value),
                                        self.options.examples_per_hit)

                if self.options.scan_json:
                    self._analyze_json(source, table, finding, value, json_paths)

            # NER просматривает лишь часть выборки — доля считается от неё
            for code in NER_CODES:
                if code in finding.hits:
                    finding.hits[code].examined = ner_examined

            for virtual in json_paths.values():
                virtual.compute_scores()
                findings[virtual.ref.full_column] = virtual

    def _ner_targets(self, values: List[str]) -> set:
        """Какие значения отдать в NER, равномерно по всей выборке.

        Раньше брались первые N свободнотекстовых значений. С выборкой
        «пополам с обоих концов» это означало, что весь бюджет уходил на
        начало таблицы, а свежие записи модель не видела вовсе.
        """
        if not self.ner.available:
            return set()
        budget = int(self.options.ner_values_per_column)
        if budget <= 0:
            return set()
        candidates = [i for i, v in enumerate(values) if self.ner.is_free_text(v)]
        if len(candidates) <= budget:
            return set(candidates)
        step = len(candidates) / budget
        return {candidates[int(i * step)] for i in range(budget)}

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
