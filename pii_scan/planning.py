# -*- coding: utf-8 -*-
"""Планирование обхода на больших схемах.

На базе в десятки гигабайт стоимость определяется не объёмом, а числом
объектов. Три приёма позволяют не сканировать всё подряд:

  1. **Группировка однотипных таблиц.** events_2026_01 … events_2026_12 или
     orders_shard_00 … orders_shard_63 — это одна и та же структура. Достаточно
     обследовать пару представителей, остальные наследуют результат с явной
     пометкой в отчёте.
  2. **Приоритет.** Таблицы, у которых имена полей уже намекают на ПДн,
     обследуются первыми: если прогон прервётся по времени, полезное успеет
     попасть в отчёт.
  3. **Бюджет времени.** Прогон завершается корректно и сохраняет то, что успел.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .detectors import detect_in_column_name
from .sources.base import ColumnInfo, TableInfo

_DIGITS_RE = re.compile(r"\d+")


def normalize_name(name: str) -> str:
    """orders_2026_08 -> orders_#_#, shard_063 -> shard_#"""
    return _DIGITS_RE.sub("#", name)


def column_signature(columns: Sequence[ColumnInfo]) -> str:
    """Подпись структуры: одинаковый набор полей — одинаковая таблица."""
    return "|".join(sorted(c.name for c in columns))


def name_score(columns: Sequence[ColumnInfo]) -> int:
    """Сколько полей таблицы уже по имени похожи на ПДн."""
    return sum(1 for c in columns if detect_in_column_name(c.name, c.comment))


@dataclass
class PlanItem:
    table: TableInfo
    columns: List[ColumnInfo]
    score: int = 0
    representative: Optional[str] = None   # если задан — результат наследуется

    @property
    def inferred(self) -> bool:
        return self.representative is not None


@dataclass
class Plan:
    items: List[PlanItem] = field(default_factory=list)
    groups: Dict[str, List[str]] = field(default_factory=dict)  # образец -> члены
    # образец -> все обследованные представители группы (их находки
    # объединяются: одна партиция может содержать то, чего нет в другой)
    representatives: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def to_scan(self) -> List[PlanItem]:
        return [i for i in self.items if not i.inferred]

    @property
    def inferred_items(self) -> List[PlanItem]:
        return [i for i in self.items if i.inferred]


def build_plan(tables: Sequence[TableInfo],
               columns_map: Dict[str, List[ColumnInfo]],
               group_similar: bool = True,
               group_min_size: int = 4,
               group_samples: int = 2) -> Plan:
    plan = Plan()
    prepared: List[PlanItem] = []
    for table in tables:
        columns = columns_map.get(table.qualified, [])
        if not columns:
            continue
        prepared.append(PlanItem(table=table, columns=columns,
                                 score=name_score(columns)))

    if group_similar and group_min_size > 1:
        buckets: Dict[tuple, List[PlanItem]] = {}
        for item in prepared:
            key = (item.table.database,
                   normalize_name(item.table.name),
                   column_signature(item.columns))
            buckets.setdefault(key, []).append(item)

        for members in buckets.values():
            if len(members) < group_min_size:
                continue
            # Представителями берём самые крупные: в них больше шансов
            # встретить редкие значения
            members.sort(key=lambda i: (i.table.rows or 0), reverse=True)
            samples = max(1, min(group_samples, len(members)))
            leader = members[0].table.qualified
            plan.groups[leader] = [m.table.qualified for m in members[samples:]]
            plan.representatives[leader] = [
                m.table.qualified for m in members[:samples]
            ]
            for member in members[samples:]:
                member.representative = leader

    # Сначала то, где ПДн вероятнее: при нехватке времени полезное успеет
    prepared.sort(key=lambda i: (-i.score, -(i.table.rows or 0),
                                 i.table.qualified))
    plan.items = prepared
    return plan
