# -*- coding: utf-8 -*-
"""Ограничение нагрузки на обследуемую СУБД.

Сканер сознательно работает в один поток, но на большой базе даже
последовательные запросы способны вымыть буферный пул: он читает первые
страницы каждой таблицы, а они вытесняют горячие данные приложения.

Инструменты сдерживания:
  * пауза между запросами (pause_ms) — самый прямой способ отдать диск;
  * потолок числа запросов в минуту (max_queries_per_minute);
  * общий бюджет времени (max_duration_min) — прогон корректно завершается
    и сохраняет то, что успел обследовать.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from .config import ThrottleOptions

log = logging.getLogger(__name__)


class Pacer:
    """Выдерживает заданный темп запросов и следит за бюджетом времени."""

    def __init__(self, throttle: Optional[ThrottleOptions] = None) -> None:
        self.throttle = throttle or ThrottleOptions()
        self._started = time.monotonic()
        self._last_query: Optional[float] = None
        self.queries = 0
        self.waited_sec = 0.0

    # --- темп ------------------------------------------------------------

    @property
    def min_interval(self) -> float:
        """Минимальный интервал между запросами, секунд."""
        interval = self.throttle.pause_ms / 1000.0
        if self.throttle.max_queries_per_minute > 0:
            interval = max(interval, 60.0 / self.throttle.max_queries_per_minute)
        return interval

    def before_query(self) -> None:
        interval = self.min_interval
        now = time.monotonic()
        if interval > 0 and self._last_query is not None:
            delay = interval - (now - self._last_query)
            if delay > 0:
                time.sleep(delay)
                self.waited_sec += delay
                now = time.monotonic()
        self._last_query = now
        self.queries += 1

    # --- бюджет времени --------------------------------------------------

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._started

    @property
    def budget_sec(self) -> float:
        return self.throttle.max_duration_min * 60.0

    def expired(self) -> bool:
        return bool(self.budget_sec) and self.elapsed >= self.budget_sec

    def remaining(self) -> Optional[float]:
        if not self.budget_sec:
            return None
        return max(0.0, self.budget_sec - self.elapsed)

    # --- прогресс --------------------------------------------------------

    def eta(self, done: int, total: int) -> str:
        """Оценка оставшегося времени по средней скорости обработки таблиц."""
        if done <= 0 or done >= total:
            return ""
        per_table = self.elapsed / done
        left = per_table * (total - done)
        if left < 90:
            return f"осталось ~{left:.0f} с"
        if left < 5400:
            return f"осталось ~{left / 60:.0f} мин"
        return f"осталось ~{left / 3600:.1f} ч"

    def summary(self) -> str:
        parts = [f"запросов: {self.queries}", f"время: {self.elapsed:.0f} с"]
        if self.waited_sec >= 1:
            parts.append(f"из них в паузах: {self.waited_sec:.0f} с")
        return ", ".join(parts)
