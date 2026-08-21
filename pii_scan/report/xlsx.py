# -*- coding: utf-8 -*-
"""Реестр в XLSX — под перечень обрабатываемых ПДн.

Три листа:
  Реестр            — уверенные находки, по одной строке на поле;
  Требует проверки  — пограничные, для ручного разбора;
  Сводка            — по таблицам и категориям.
"""
from __future__ import annotations

from typing import List, Optional

from ..model import Finding, ScanResult

REGISTRY_HEADER = [
    "Источник", "СУБД", "База данных", "Таблица", "Поле", "Тип поля",
    "Категория ПДн", "Вид ПДн", "Третьи лица", "Уверенность", "Основание",
    "Совпало значений", "Строк в таблице", "Комментарий к полю",
    "Примеры (маскированные)",
]

SUMMARY_HEADER = [
    "Источник", "База данных", "Таблица", "Полей с ПДн", "Категории",
    "Спецкатегории", "Третьи лица", "Строк в таблице", "Уверенность",
]


def _require_openpyxl():
    try:
        import openpyxl  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "для выгрузки XLSX нужен openpyxl (pip install openpyxl)"
        ) from exc
    return __import__("openpyxl")


def _row(finding: Finding, source_type: str) -> List:
    examples: List[str] = []
    for code in finding.codes:
        for ex in finding.hits[code].examples:
            if ex not in examples:
                examples.append(ex)
    return [
        finding.ref.source,
        source_type,
        finding.ref.database,
        finding.ref.table,
        finding.ref.full_column,
        finding.ref.data_type,
        ", ".join(finding.categories) or "—",
        ", ".join(finding.titles),
        "да" if finding.third_party else "",
        round(finding.score, 2),
        finding.basis,
        finding.coverage,
        finding.rows_total if finding.rows_total is not None else "",
        finding.ref.comment,
        "; ".join(examples[:3]),
    ]


def write_xlsx(result: ScanResult, path: str) -> None:
    openpyxl = _require_openpyxl()
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    types = {s["name"]: s["type"] for s in result.sources}

    wb = openpyxl.Workbook()
    head_font = Font(bold=True, color="FFFFFF")
    head_fill = PatternFill("solid", fgColor="44546A")
    special_fill = PatternFill("solid", fgColor="FCE4D6")

    def setup(ws, header: List[str]) -> None:
        ws.append(header)
        for cell in ws[1]:
            cell.font = head_font
            cell.fill = head_fill
            cell.alignment = Alignment(vertical="center", wrap_text=True)
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = f"A1:{get_column_letter(len(header))}1"

    def autosize(ws, widths: Optional[List[int]] = None) -> None:
        for idx in range(1, ws.max_column + 1):
            letter = get_column_letter(idx)
            if widths and idx <= len(widths):
                ws.column_dimensions[letter].width = widths[idx - 1]
                continue
            longest = max(
                (len(str(c.value)) for c in ws[letter] if c.value is not None),
                default=10,
            )
            ws.column_dimensions[letter].width = min(max(longest + 2, 10), 45)

    # --- Реестр ---
    ws = wb.active
    ws.title = "Реестр"
    setup(ws, REGISTRY_HEADER)
    for table in result.pii_tables:
        for finding in table.pii_findings:
            ws.append(_row(finding, types.get(finding.ref.source, "")))
            if "специальные" in finding.categories:
                for cell in ws[ws.max_row]:
                    cell.fill = special_fill
    autosize(ws)

    # --- Требует проверки ---
    ws = wb.create_sheet("Требует проверки")
    setup(ws, REGISTRY_HEADER)
    for table in result.tables:
        for finding in table.maybe_findings:
            ws.append(_row(finding, types.get(finding.ref.source, "")))
    autosize(ws)

    # --- Сводка ---
    ws = wb.create_sheet("Сводка")
    setup(ws, SUMMARY_HEADER)
    for table in result.pii_tables:
        ws.append([
            table.source, table.database, table.table,
            len(table.pii_findings), ", ".join(table.categories) or "—",
            "да" if table.has_special else "",
            "да" if table.third_party else "",
            table.rows_total if table.rows_total is not None else "",
            round(table.score, 2),
        ])
        if table.has_special:
            for cell in ws[ws.max_row]:
                cell.fill = special_fill
    ws.append([])
    ws.append(["Обследование проведено", result.started_at])
    ws.append(["Длительность, с", result.duration_sec])
    ws.append(["Режим", "инвентаризация схемы"
               if result.options.get("dry_run") else "выборка значений"])
    ws.append(["Таблиц с ПДн", len(result.pii_tables)])
    ws.append(["Таблиц на проверку", len(result.maybe_tables)])
    autosize(ws)

    wb.save(path)
