# -*- coding: utf-8 -*-
"""Вывод результата в терминал."""
from __future__ import annotations

import sys
from typing import List

from ..model import ScanResult, TableStat, VERDICT_TITLES

MAX_ROWS = 40


def _table(rows: List[List[str]], header: List[str]) -> str:
    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(header))
    out = [line, "  ".join("-" * w for w in widths)]
    for row in rows:
        out.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(out)


def _kinds(table: TableStat, limit: int = 4) -> str:
    kinds = sorted({t for f in table.pii_findings or table.maybe_findings
                    for t in f.titles})
    text = ", ".join(kinds[:limit])
    return text + (f" (+{len(kinds) - limit})" if len(kinds) > limit else "")


def _reason(table: TableStat) -> str:
    """На чём держится пограничный вывод — от этого зависит, кому его отдавать."""
    if any(f.confirmed_by_values for f in table.maybe_findings):
        return "значения"
    return "только имя поля"


def render_details(result: ScanResult) -> str:
    """Разбивка по полям — то, что передают разработчикам на проверку.

    Табличная сводка отвечает на вопрос «где искать», а этот вывод — на
    «что именно и на каком основании»: поле, вид ПДн, откуда взят вывод,
    сколько значений выборки совпало.
    """
    out: List[str] = []
    full = bool(result.options.get("full_inventory"))
    examples = bool(result.options.get("examples_per_hit"))
    tables = result.tables if full else result.pii_tables + result.maybe_tables
    if not tables:
        return ""

    out.append("")
    out.append("=" * 72)
    out.append("ПОЛНАЯ ОПИСЬ ПОЛЕЙ" if full else "ДЕТАЛИЗАЦИЯ ПО ПОЛЯМ")
    out.append("=" * 72)
    if full:
        out.append("Перечислены все поля всех обследованных таблиц, включая "
                   "те, где ПДн не обнаружены.")

    for table in tables:
        findings = (table.findings if full
                    else [f for f in table.findings if f.verdict != "no"])
        if not findings:
            continue
        note = f"  [по образцу {table.inferred_from}]" if table.inferred_from else ""
        out.append("")
        out.append(f"{table.qualified}   (источник {table.source}){note}")
        rows = []
        header = ["Поле", "Тип"]
        if full:
            header.append("Вердикт")
        header += ["Вид ПДн", "Категория", "Основание", "Совпало", "Увер."]
        if examples:
            header.append("Примеры (маск.)")
        for f in sorted(findings, key=lambda x: (-x.score, x.ref.full_column)):
            row = [f.ref.full_column, f.ref.data_type or "—"]
            if full:
                row.append(VERDICT_TITLES[f.verdict])
            row += [
                f.summary_kind if full else ", ".join(f.titles),
                ", ".join(f.categories) or "—",
                f.basis,
                f.coverage,
                f"{f.score:.0%}" if f.score else "—",
            ]
            if examples:
                row.append("; ".join(_examples(f)) or "—")
            rows.append(row)
        out.append(_indent(_table(rows, header)))

    out.append("")
    return "\n".join(out)


def _examples(finding) -> List[str]:
    seen: List[str] = []
    for code in finding.codes:
        for example in finding.hits[code].examples:
            if example not in seen:
                seen.append(example)
    return seen[:2]


def _indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line for line in text.split("\n"))


def render(result: ScanResult) -> str:
    out: List[str] = []
    pii = result.pii_tables

    out.append("")
    out.append("=" * 72)
    out.append("РЕЗУЛЬТАТ ПОИСКА ПЕРСОНАЛЬНЫХ ДАННЫХ")
    out.append("=" * 72)
    for src in result.sources:
        flag = "" if src.get("read_only") else "  [есть права на запись!]"
        out.append(f"  {src['name']:<16} {src['type']:<11} {src['host']:<22} "
                   f"таблиц: {src['tables']}{flag}")
    out.append("")
    out.append(f"  Таблиц с ПДн:            {len(pii)}")
    out.append(f"  Из них спецкатегории:    {sum(1 for t in pii if t.has_special)}")
    out.append(f"  Из них третьи лица:      {sum(1 for t in pii if t.third_party)}")
    pending = result.pending_findings
    out.append(f"  Требуют проверки:        {len(result.maybe_tables)} "
               f"табл. / {len(pending)} полей")
    # В режиме --dry-run значения не читались вовсе, поэтому «только по
    # имени поля» там верно для всего подряд и ничего не различает.
    if pending and not result.options.get("dry_run"):
        out.append(f"    подтверждено значениями: "
                   f"{len(result.pending_confirmed)}")
        out.append(f"    только по имени поля:    "
                   f"{len(result.pending_by_name)}")
    elif pending:
        out.append("    значения не читались — вывод только по именам полей")
    out.append(f"  Длительность:            {result.duration_sec} с")
    if result.options.get("detectors_limited"):
        out.append(f"  Искали только:           "
                   f"{result.options.get('detectors')}")
    out.append("")

    if pii:
        rows = [
            [t.qualified, _kinds(t), ", ".join(t.categories) or "—",
             t.rows_display, f"{t.score:.0%}"]
            for t in pii[:MAX_ROWS]
        ]
        out.append("ТАБЛИЦЫ С ПДн")
        out.append(_table(rows, ["Таблица", "Виды ПДн", "Категория",
                                 "Строк", "Увер."]))
        if len(pii) > MAX_ROWS:
            out.append(f"  … ещё {len(pii) - MAX_ROWS}, полный список в отчётах")
        out.append("")

    if result.maybe_tables:
        rows = [
            [t.qualified, _kinds(t), _reason(t), f"{t.score:.0%}"]
            for t in result.maybe_tables[:MAX_ROWS]
        ]
        out.append("ТРЕБУЮТ РУЧНОЙ ПРОВЕРКИ")
        out.append(_table(rows, ["Таблица", "Предположительно", "На чём держится",
                                 "Увер."]))
        if len(result.maybe_tables) > MAX_ROWS:
            out.append(f"  … ещё {len(result.maybe_tables) - MAX_ROWS}")
        out.append("")

    if result.warnings:
        out.append("ПРЕДУПРЕЖДЕНИЯ")
        out += [f"  ! {w}" for w in result.warnings]
        out.append("")
    if result.errors:
        out.append("ОШИБКИ")
        out += [f"  x {e}" for e in result.errors]
        out.append("")

    return "\n".join(out)


def print_result(result: ScanResult, details: bool = False) -> None:
    print(render(result), file=sys.stdout)
    if details:
        print(render_details(result), file=sys.stdout)
