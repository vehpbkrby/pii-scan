# -*- coding: utf-8 -*-
"""Два отчёта в Markdown.

summary.md  — лёгкий: только уверенные находки, одна строка на таблицу.
              Это то, что показывают владельцу системы и руководителю.
detailed.md — подробный: все находки, включая пограничные, с основанием
              вывода и замаскированными примерами.
"""
from __future__ import annotations

from typing import List

from ..model import Finding, ScanResult, TableStat


def _fmt_score(score: float) -> str:
    return f"{score:.0%}"


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _flags(table: TableStat) -> str:
    marks = []
    if table.has_special:
        marks.append("**спецкатегории**")
    if table.third_party:
        marks.append("третьи лица")
    if table.inferred_from:
        marks.append(f"по образцу `{table.inferred_from}`")
    return ", ".join(marks) or "—"


def _header(result: ScanResult, title: str) -> List[str]:
    mode = "инвентаризация схемы (данные не читались)" \
        if result.options.get("dry_run") else "выборка значений"
    lines = [
        f"# {title}",
        "",
        f"* Дата проведения: {result.started_at}",
        f"* Длительность: {result.duration_sec} с",
        f"* Режим: {mode}",
    ]
    if not result.options.get("dry_run"):
        strategy = {
            "head": "начало таблицы",
            "tail": "конец таблицы",
            "head_tail": "пополам с начала и с конца",
        }.get(result.options.get("sample_strategy"), "начало таблицы")
        lines.append(f"* Строк выборки на таблицу: "
                     f"{result.options.get('sample_limit')} ({strategy})")
        lines.append(f"* Разбор JSON: "
                     f"{'да' if result.options.get('scan_json') else 'нет'}; "
                     f"NER по тексту: "
                     f"{'да' if result.options.get('ner') else 'нет'}")
    lines.append("")
    lines.append("Обследованные источники:")
    lines.append("")
    lines.append("| Источник | СУБД | Адрес | Учётная запись | Таблиц | Только чтение |")
    lines.append("|---|---|---|---|---|---|")
    for src in result.sources:
        lines.append(
            f"| {src['name']} | {src['type']} | {src['host']} | {src['user']} | "
            f"{src['tables']} | {'да' if src.get('read_only') else '**нет**'} |"
        )
    lines.append("")
    return lines


# --- лёгкий отчёт -----------------------------------------------------------

def render_summary(result: ScanResult) -> str:
    lines = _header(result, "Персональные данные в БД: сводка")

    pii = result.pii_tables
    lines += [
        "## Итог",
        "",
        f"* Таблиц с персональными данными: **{len(pii)}**",
        f"* Из них со специальными категориями (ст. 10 152-ФЗ): "
        f"**{sum(1 for t in pii if t.has_special)}**",
        f"* Из них с данными третьих лиц (родственники): "
        f"**{sum(1 for t in pii if t.third_party)}**",
        f"* Таблиц, требующих ручной проверки: **{len(result.maybe_tables)}**",
        "",
    ]

    if pii:
        lines += [
            "## Таблицы, содержащие ПДн",
            "",
            "| Источник | Таблица | Виды ПДн | Особые отметки | Строк | Уверенность |",
            "|---|---|---|---|---|---|",
        ]
        for table in pii:
            kinds = sorted({t for f in table.pii_findings for t in f.titles})
            lines.append(
                f"| {table.source} | `{table.qualified}` | "
                f"{_escape(', '.join(kinds))} | {_flags(table)} | "
                f"{table.rows_display} | {_fmt_score(table.score)} |"
            )
        lines.append("")
    else:
        lines += ["## Таблицы, содержащие ПДн", "",
                  "Уверенных находок нет.", ""]

    if result.maybe_tables:
        lines += [
            "## Требуют ручной проверки",
            "",
            "Сигналов недостаточно для однозначного вывода — "
            "проверьте содержимое вручную.",
            "",
            "| Источник | Таблица | Предположительно | Уверенность |",
            "|---|---|---|---|",
        ]
        for table in result.maybe_tables:
            kinds = sorted({t for f in table.maybe_findings for t in f.titles})
            lines.append(
                f"| {table.source} | `{table.qualified}` | "
                f"{_escape(', '.join(kinds))} | {_fmt_score(table.score)} |"
            )
        lines.append("")

    lines += _footer(result)
    return "\n".join(lines)


# --- подробный отчёт --------------------------------------------------------

def _finding_row(finding: Finding) -> str:
    examples = []
    for code in finding.codes:
        examples += finding.hits[code].examples
    seen, uniq = set(), []
    for ex in examples:
        if ex not in seen:
            seen.add(ex)
            uniq.append(ex)
    return (
        f"| `{_escape(finding.ref.full_column)}` | "
        f"{_escape(finding.ref.data_type)} | "
        f"{_escape(', '.join(finding.titles))} | "
        f"{', '.join(finding.categories) or '—'} | "
        f"{finding.basis} | {finding.coverage} | {_fmt_score(finding.score)} | "
        f"{_escape(', '.join(uniq[:3])) or '—'} |"
    )


def render_detailed(result: ScanResult) -> str:
    lines = _header(result, "Персональные данные в БД: подробный отчёт")

    lines += [
        "## Как читать отчёт",
        "",
        "* **Основание** — откуда взят вывод: имя поля, значения в выборке, NER.",
        "* **Совпало** — сколько значений выборки распозналось как ПДн.",
        "* Поля вида `payload::$.client.phone` — ключи внутри JSON-значения.",
        "* Примеры значений замаскированы; сами ПДн в отчёт не выгружаются.",
        "* СНИЛС, ИНН, полис ОМС и номера карт проверены по контрольной сумме — "
        "ложные срабатывания на них практически исключены.",
        "* Специальные категории и сведения о родственниках определяются "
        "по именам полей, поэтому требуют подтверждения владельцем системы.",
        "* Пометка «по образцу» означает, что таблица однотипна обследованной "
        "(одинаковые имя с точностью до чисел и набор полей) и результат "
        "перенесён с неё, а сами данные не читались.",
        "",
    ]

    for section, tables in (("Таблицы с ПДн", result.pii_tables),
                            ("Требуют ручной проверки", result.maybe_tables)):
        if not tables:
            continue
        lines += [f"## {section}", ""]
        for table in tables:
            lines += [
                f"### `{table.qualified}` — источник {table.source}",
                "",
                f"Строк в таблице: {table.rows_display} · "
                f"прочитано в выборке: {table.rows_sampled} · "
                f"колонок: {table.columns_total} · "
                f"отметки: {_flags(table)}",
                "",
                "| Поле | Тип | Вид ПДн | Категория | Основание | Совпало | "
                "Уверенность | Примеры (маск.) |",
                "|---|---|---|---|---|---|---|---|",
            ]
            for finding in table.findings:
                if finding.verdict == "no":
                    continue
                lines.append(_finding_row(finding))
            lines.append("")

    lines += _footer(result)
    return "\n".join(lines)


def _footer(result: ScanResult) -> List[str]:
    lines: List[str] = []
    if result.warnings:
        lines += ["## Предупреждения", ""]
        lines += [f"* {_escape(w)}" for w in result.warnings]
        lines.append("")
    if result.errors:
        lines += ["## Ошибки", ""]
        lines += [f"* {_escape(e)}" for e in result.errors]
        lines.append("")
    lines += [
        "---",
        "",
        "Отчёт получен автоматизированным поиском по образцу данных. "
        "Результат — основание для проверки, а не юридическая квалификация: "
        "решение об отнесении сведений к персональным данным принимает оператор.",
    ]
    return lines


def write_summary(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_summary(result))


def write_detailed(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_detailed(result))
