# -*- coding: utf-8 -*-
"""Индикатор выполнения.

На большой базе прогон идёт минутами, и оператору нужно понимать, сколько
осталось. В терминале рисуется полоса, перерисовываемая на месте; если вывод
перенаправлен в файл или в журнал (cron, systemd), полоса не рисуется —
вместо неё редкие строки в лог, чтобы не засорять его сотнями записей.
"""
from __future__ import annotations

import shutil
import sys
from typing import Optional, TextIO

FILLED = "█"
EMPTY = "░"
MIN_BAR = 10
MAX_BAR = 40

_active: Optional["ProgressBar"] = None


def active() -> Optional["ProgressBar"]:
    """Текущая полоса — нужна обработчику логов, чтобы её не ломать."""
    return _active


class ProgressBar:
    """Полоса выполнения в одну строку.

    mode: auto — рисовать только в терминале, on — всегда, off — никогда.
    """

    def __init__(self, total: int, mode: str = "auto", title: str = "",
                 stream: Optional[TextIO] = None) -> None:
        self.total = max(0, int(total))
        self.title = title
        self.stream = stream or sys.stderr
        self.done = 0
        self.label = ""
        self.suffix = ""
        self._last_line = ""
        self.enabled = self._resolve(mode) and self.total > 0

    def _resolve(self, mode: str) -> bool:
        if mode == "off":
            return False
        if mode == "on":
            return True
        try:
            return bool(self.stream.isatty())
        except (AttributeError, ValueError):
            return False

    # --- отрисовка --------------------------------------------------------

    def __enter__(self) -> "ProgressBar":
        global _active
        if self.enabled:
            _active = self
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def advance(self, label: str = "", suffix: str = "") -> None:
        self.done += 1
        self.label = label
        self.suffix = suffix
        self.redraw()

    def _compose(self) -> str:
        width = shutil.get_terminal_size((100, 24)).columns
        share = self.done / self.total if self.total else 1.0
        percent = f"{share * 100:3.0f}%"
        counter = f"{self.done}/{self.total}"
        head = f"{self.title} " if self.title else ""
        tail = f" {counter} {percent}"
        if self.suffix:
            tail += f" · {self.suffix}"

        bar_width = max(MIN_BAR, min(MAX_BAR, width - len(head) - len(tail) - 20))
        filled = int(bar_width * share)
        bar = FILLED * filled + EMPTY * (bar_width - filled)

        line = f"{head}[{bar}]{tail}"
        # два пробела-разделителя плюс запас, чтобы строка не упёрлась в край
        room = width - len(line) - 3
        if self.label and room > 8:
            label = self.label
            if len(label) > room:
                label = "…" + label[-(room - 1):]
            line = f"{line}  {label}"
        return line[:width - 1]

    def redraw(self) -> None:
        if not self.enabled:
            return
        line = self._compose()
        self._last_line = line
        try:
            self.stream.write("\r" + line + "\x1b[K")
            self.stream.flush()
        except (OSError, ValueError, UnicodeEncodeError):
            self.enabled = False

    def clear(self) -> None:
        """Стереть полосу — перед выводом обычной строки лога."""
        if not self.enabled or not self._last_line:
            return
        try:
            self.stream.write("\r\x1b[K")
            self.stream.flush()
        except (OSError, ValueError):
            self.enabled = False

    def close(self) -> None:
        global _active
        if self.enabled and self._last_line:
            try:
                self.stream.write("\n")
                self.stream.flush()
            except (OSError, ValueError):
                pass
        if _active is self:
            _active = None
        self._last_line = ""
