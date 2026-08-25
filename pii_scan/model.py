# -*- coding: utf-8 -*-
"""Модель находок и правила скоринга."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .detectors import DETECTORS_BY_CODE, CATEGORY_ORDER

# Пороги уверенности
VERDICT_PII = 0.70        # уверенно ПДн — попадает в лёгкий отчёт
VERDICT_MAYBE = 0.35      # требует ручной проверки
NAME_BOOST = 0.35         # вклад совпадения по имени колонки
# У части правил имя поля само по себе решает: `diagnosis`, `emergency_contact`
# двусмысленности не оставляют, а цена пропуска высокая. Такая колонка сразу
# считается ПДн, если в ней есть данные, и уходит на проверку, если она пуста.
# Значения при этом читаются и проверяются как у всех остальных колонок —
# просто их совпадение уже ничего не добавляет к и без того ясному выводу.
NAME_CONCLUSIVE_SCORE = 0.75
NAME_CONCLUSIVE_EMPTY = 0.50
# Порог «наличия» для детекторов свободного текста (NER)
PRESENCE_MIN_HITS = 3
PRESENCE_MIN_RATIO = 0.05

VERDICT_TITLES = {
    "pii": "ПДн",
    "maybe": "требует проверки",
    "no": "не обнаружено",
}


@dataclass
class ColumnRef:
    """Адрес колонки. json_path заполняется для полей внутри JSON-значений."""
    source: str
    database: str
    table: str
    column: str
    data_type: str = ""
    comment: str = ""
    json_path: Optional[str] = None

    @property
    def full_column(self) -> str:
        return f"{self.column}::{self.json_path}" if self.json_path else self.column

    @property
    def qualified(self) -> str:
        return f"{self.database}.{self.table}.{self.full_column}"


@dataclass
class Hit:
    """Свидетельства по одному детектору в одной колонке."""
    code: str
    by_name: bool = False
    matched: int = 0            # сколько значений выборки совпало
    examined: int = 0           # сколько проверено (0 = вся выборка колонки)
    examples: List[str] = field(default_factory=list)  # замаскированные

    def add_example(self, masked: str, limit: int = 3) -> None:
        if len(self.examples) < limit and masked not in self.examples:
            self.examples.append(masked)


@dataclass
class Finding:
    ref: ColumnRef
    rows_total: Optional[int] = None    # оценка размера таблицы
    sampled: int = 0                    # прочитано строк
    non_null: int = 0                   # непустых значений в колонке
    hits: Dict[str, Hit] = field(default_factory=dict)
    scores: Dict[str, float] = field(default_factory=dict)
    dry_run: bool = False       # данные не читались — «пусто» ≠ «не смотрели»
    inferred_from: Optional[str] = None  # результат образца однотипной таблицы

    def hit(self, code: str) -> Hit:
        if code not in self.hits:
            self.hits[code] = Hit(code=code)
        return self.hits[code]

    # --- скоринг ---------------------------------------------------------

    def compute_scores(self) -> None:
        """score = доля совпавших значений × вес детектора (+ бонус за имя)."""
        self.scores = {}
        for code, hit in self.hits.items():
            det = DETECTORS_BY_CODE.get(code)
            if det is None:
                continue
            has_data = self.non_null > 0 or self.dry_run
            # Знаменатель — сколько значений реально проверялось этим
            # детектором. У NER бюджет ограничен, и делить его попадания
            # на всю выборку значит занижать результат в разы.
            denominator = hit.examined or self.non_null
            ratio = hit.matched / denominator if denominator else 0.0
            if det.presence_based:
                # Для свободного текста важен факт наличия ПДн, а не доля:
                # колонка с ФИО в каждом двадцатом комментарии — носитель
                # персональных данных ничуть не меньше, чем в каждом.
                score = det.weight if (
                    hit.matched >= PRESENCE_MIN_HITS
                    or ratio >= PRESENCE_MIN_RATIO
                ) else ratio * det.weight
            else:
                score = ratio * det.weight
            if hit.by_name:
                score += NAME_BOOST
            if det.name_conclusive and hit.by_name:
                # Имя не оставляет двусмысленности — вывод не зависит от того,
                # удалось ли распознать сами значения. Берём максимум: если
                # значения тоже совпали, оценка от этого только вырастет.
                score = max(score,
                            NAME_CONCLUSIVE_SCORE if has_data
                            else NAME_CONCLUSIVE_EMPTY)
            if hit.by_name and self.non_null == 0 and not self.dry_run:
                # колонка действительно пустая — верим только имени
                score = max(score, NAME_CONCLUSIVE_EMPTY)
            self.scores[code] = round(min(score, 1.0), 3)

    @property
    def score(self) -> float:
        return max(self.scores.values(), default=0.0)

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= VERDICT_PII:
            return "pii"
        if s >= VERDICT_MAYBE:
            return "maybe"
        return "no"

    @property
    def codes(self) -> List[str]:
        """Сработавшие детекторы, от самого уверенного к наименее."""
        return [
            c for c, _ in sorted(
                self.scores.items(), key=lambda kv: kv[1], reverse=True
            ) if self.scores[c] >= VERDICT_MAYBE
        ]

    @property
    def titles(self) -> List[str]:
        return [DETECTORS_BY_CODE[c].title for c in self.codes if c in DETECTORS_BY_CODE]

    @property
    def categories(self) -> List[str]:
        cats = {DETECTORS_BY_CODE[c].category for c in self.codes
                if c in DETECTORS_BY_CODE}
        return [c for c in CATEGORY_ORDER if c in cats]

    @property
    def third_party(self) -> bool:
        return any(DETECTORS_BY_CODE[c].third_party for c in self.codes
                   if c in DETECTORS_BY_CODE)

    @property
    def weak_titles(self) -> List[str]:
        """Совпадения ниже порога — для полной описи полей.

        Такое поле в находки не попадает, но в описи честнее показать, что
        сигнал был и почему его сочли недостаточным.
        """
        weak = [
            (code, score) for code, score in self.scores.items()
            if 0 < score < VERDICT_MAYBE and code in DETECTORS_BY_CODE
        ]
        weak.sort(key=lambda item: -item[1])
        return [
            f"{DETECTORS_BY_CODE[code].title} ({score:.0%})"
            for code, score in weak[:2]
        ]

    @property
    def summary_kind(self) -> str:
        """Вид ПДн для описи: находка, слабый сигнал или пусто."""
        if self.titles:
            return ", ".join(self.titles)
        if self.weak_titles:
            return "слабый признак: " + ", ".join(self.weak_titles)
        return "—"

    @property
    def coverage(self) -> str:
        """Доля значений выборки, распознанных как ПДн.

        Для детекторов, работающих только по имени поля, значения ни при чём —
        показывать «0/3» было бы враньём.
        """
        codes = [c for c in self.codes
                 if c in DETECTORS_BY_CODE and not DETECTORS_BY_CODE[c].name_only]
        if not codes or not self.non_null:
            return "—"
        matched = max(self.hits[c].matched for c in codes)
        return f"{matched}/{self.non_null}"

    @property
    def basis(self) -> str:
        """Основание вывода — для колонки «Основание» в реестре."""
        if self.inferred_from:
            return f"по образцу {self.inferred_from}"
        parts = []
        codes = set(self.codes)
        if any(self.hits[c].by_name for c in codes if c in self.hits):
            parts.append("имя поля")
        if any(self.hits[c].matched for c in codes if c in self.hits):
            parts.append("значения")
        if codes & {"ner_person", "ner_location"}:
            parts.append("NER")
        return ", ".join(parts) or "—"


@dataclass
class TableStat:
    """Итог по таблице — основа лёгкого отчёта."""
    source: str
    database: str
    table: str
    rows_total: Optional[int]
    findings: List[Finding] = field(default_factory=list)
    columns_total: int = 0
    rows_sampled: int = 0
    inferred_from: Optional[str] = None   # обследован образец однотипной таблицы

    @property
    def qualified(self) -> str:
        return f"{self.database}.{self.table}"

    @property
    def rows_display(self) -> str:
        """Размер таблицы — оценка СУБД, а не COUNT(*).

        В MySQL information_schema.TABLE_ROWS для InnoDB берётся из статистики
        и бывает занижена в сотни раз. Если мы прочитали больше строк, чем
        обещала статистика, честнее показать «не меньше прочитанного».
        """
        if self.rows_total is None:
            return "н/д"
        if self.rows_sampled > self.rows_total:
            return f"≥ {self.rows_sampled}"
        return f"≈ {self.rows_total}"

    @property
    def pii_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.verdict == "pii"]

    @property
    def maybe_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.verdict == "maybe"]

    @property
    def categories(self) -> List[str]:
        cats = set()
        for f in self.pii_findings:
            cats.update(f.categories)
        return [c for c in CATEGORY_ORDER if c in cats]

    @property
    def has_special(self) -> bool:
        return "специальные" in self.categories

    @property
    def third_party(self) -> bool:
        return any(f.third_party for f in self.pii_findings)

    @property
    def score(self) -> float:
        return max((f.score for f in self.findings), default=0.0)


@dataclass
class ScanResult:
    started_at: str = ""
    finished_at: str = ""
    duration_sec: float = 0.0
    options: Dict[str, object] = field(default_factory=dict)
    sources: List[Dict[str, object]] = field(default_factory=list)
    tables: List[TableStat] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def pii_tables(self) -> List[TableStat]:
        return sorted(
            [t for t in self.tables if t.pii_findings],
            key=lambda t: (not t.has_special, -t.score, t.qualified),
        )

    @property
    def maybe_tables(self) -> List[TableStat]:
        return sorted(
            [t for t in self.tables if not t.pii_findings and t.maybe_findings],
            key=lambda t: (-t.score, t.qualified),
        )

    @property
    def all_findings(self) -> List[Finding]:
        return [f for t in self.tables for f in t.findings]
