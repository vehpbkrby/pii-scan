# -*- coding: utf-8 -*-
"""Вывод результата в терминал."""
from __future__ import annotations

import sys
from typing import List

from ..model import ScanResult, TableStat

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


def render_details(result: ScanResult) -> str:
    """Разбивка по полям — то, что передают разработчикам на проверку.

    Табличная сводка отвечает на вопрос «где искать», а этот вывод — на
    «что именно и на каком основании»: поле, вид ПДн, откуда взят вывод,
    сколько значений выборки совпало.
    """
    out: List[str] = []
    tables = result.pii_tables + result.maybe_tables
    if not tables:
        return ""

    out.append("")
    out.append("=" * 72)
    out.append("ДЕТАЛИЗАЦИЯ ПО ПОЛЯМ")
    out.append("=" * 72)

    for table in tables:
        findings = [f for f in table.findings if f.verdict != "no"]
        if not findings:
            continue
        note = f"  [по образцу {table.inferred_from}]" if table.inferred_from else ""
        out.append("")
        out.append(f"{table.qualified}   (источник {table.source}){note}")
        rows = [
            [
                f.ref.full_column,
                f.ref.data_type or "—",
                ", ".join(f.titles),
                ", ".join(f.categories) or "—",
                f.basis,
                f.coverage,
                f"{f.score:.0%}",
                "; ".join(_examples(f)) or "—",
            ]
            for f in findings
        ]
        out.append(_indent(_table(rows, [
            "Поле", "Тип", "Вид ПДн", "Категория", "Основание", "Совпало",
            "Увер.", "Примеры (маск.)",
        ])))

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
    out.append(f"  Требуют проверки:        {len(result.maybe_tables)}")
    out.append(f"  Длительность:            {result.duration_sec} с")
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
            [t.qualified, _kinds(t), f"{t.score:.0%}"]
            for t in result.maybe_tables[:MAX_ROWS]
        ]
        out.append("ТРЕБУЮТ РУЧНОЙ ПРОВЕРКИ")
        out.append(_table(rows, ["Таблица", "Предположительно", "Увер."]))
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
