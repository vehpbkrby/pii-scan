# -*- coding: utf-8 -*-
"""Полная выгрузка результата в JSON — для скриптов и сравнения прогонов."""
from __future__ import annotations

import json
from typing import Any, Dict

from ..detectors import DETECTORS_BY_CODE
from ..model import Finding, ScanResult, TableStat, VERDICT_TITLES


def finding_to_dict(finding: Finding) -> Dict[str, Any]:
    return {
        "source": finding.ref.source,
        "database": finding.ref.database,
        "table": finding.ref.table,
        "column": finding.ref.column,
        "json_path": finding.ref.json_path,
        "data_type": finding.ref.data_type,
        "comment": finding.ref.comment,
        "rows_total": finding.rows_total,
        "sampled": finding.sampled,
        "non_null": finding.non_null,
        "score": finding.score,
        "verdict": finding.verdict,
        "verdict_title": VERDICT_TITLES[finding.verdict],
        "categories": finding.categories,
        "third_party": finding.third_party,
        "basis": finding.basis,
        "inferred_from": finding.inferred_from,
        "detectors": [
            {
                "code": code,
                "title": DETECTORS_BY_CODE[code].title,
                "category": DETECTORS_BY_CODE[code].category,
                "score": finding.scores.get(code, 0.0),
                "by_name": finding.hits[code].by_name,
                "matched": finding.hits[code].matched,
                "examples": finding.hits[code].examples,
            }
            for code in sorted(finding.hits, key=lambda c: -finding.scores.get(c, 0.0))
            if code in DETECTORS_BY_CODE
        ],
    }


def table_to_dict(table: TableStat) -> Dict[str, Any]:
    return {
        "source": table.source,
        "database": table.database,
        "table": table.table,
        "rows_total": table.rows_total,
        "rows_sampled": table.rows_sampled,
        "inferred_from": table.inferred_from,
        "columns_total": table.columns_total,
        "categories": table.categories,
        "has_special": table.has_special,
        "third_party": table.third_party,
        "score": table.score,
        "findings": [finding_to_dict(f) for f in table.findings],
    }


def result_to_dict(result: ScanResult) -> Dict[str, Any]:
    return {
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_sec": result.duration_sec,
        "options": result.options,
        "sources": result.sources,
        "summary": {
            "tables_with_pii": len(result.pii_tables),
            "tables_to_review": len(result.maybe_tables),
            "columns_with_pii": sum(
                len(t.pii_findings) for t in result.tables),
            "tables_with_special": sum(
                1 for t in result.pii_tables if t.has_special),
            "tables_with_third_party": sum(
                1 for t in result.pii_tables if t.third_party),
        },
        "tables": [table_to_dict(t) for t in result.tables],
        "warnings": result.warnings,
        "errors": result.errors,
    }


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result_to_dict(result), fh, ensure_ascii=False, indent=2)
