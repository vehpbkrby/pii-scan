# -*- coding: utf-8 -*-
"""Вывод результата в терминал."""
from __future__ import annotations

import sys
from typing import List, Optional

from ..model import ScanResult, TableStat

MAX_ROWS = 40


def _fmt_rows(rows: Optional[int]) -> str:
    if rows is None:
        return "н/д"
    if rows >= 1_000_000:
        return f"{rows / 1_000_000:.1f}M"
    if rows >= 1_000:
        return f"{rows // 1_000}k"
    return str(rows)


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
             _fmt_rows(t.rows_total), f"{t.score:.0%}"]
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


def print_result(result: ScanResult) -> None:
    print(render(result), file=sys.stdout)
