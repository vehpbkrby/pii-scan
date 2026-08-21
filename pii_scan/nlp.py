# -*- coding: utf-8 -*-
"""NER по русскому тексту (natasha). Полностью локально, без сети.

Модели navec/slovnet упакованы внутрь пакета natasha и загружаются с диска.
Ни при инициализации, ни при разборе текста наружу ничего не отправляется —
в этом модуле нет и не должно быть HTTP-клиента.

Если natasha не установлена (образ pii-scan:slim), класс работает как заглушка:
метод analyze() всегда возвращает пустое множество, сканер продолжает работу
только на regex-детекторах.
"""
from __future__ import annotations

import logging
import re
from typing import Set

log = logging.getLogger(__name__)

# Текст короче — почти наверняка структурное поле, NER там не нужен.
MIN_TEXT_LEN = 12
# Текст длиннее обрезается: инференс линеен по длине.
MAX_TEXT_LEN = 2000

_CYRILLIC = re.compile(r"[А-Яа-яЁё]")
_HAS_SPACE = re.compile(r"\s")


class NerTagger:
    """Ленивая обёртка над natasha. Модели грузятся при первом обращении."""

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._loaded = False
        self._broken = False
        self._segmenter = None
        self._tagger = None
        self.calls = 0

    # --- жизненный цикл ---------------------------------------------------

    def _load(self) -> bool:
        if self._loaded:
            return True
        if self._broken or not self._enabled:
            return False
        try:
            from natasha import NewsEmbedding, NewsNERTagger, Segmenter
        except ImportError:
            log.info("natasha не установлена — NER отключён "
                     "(соберите образ с --build-arg WITH_NLP=1)")
            self._broken = True
            return False
        try:
            log.info("Загрузка моделей NER (локально, без сети)…")
            self._segmenter = Segmenter()
            self._tagger = NewsNERTagger(NewsEmbedding())
            self._loaded = True
            log.info("Модели NER загружены")
            return True
        except Exception as exc:  # noqa: BLE001 — падать из-за NER не должны
            log.warning("Не удалось загрузить модели NER: %s", exc)
            self._broken = True
            return False

    @property
    def available(self) -> bool:
        return self._enabled and not self._broken

    # --- разбор -----------------------------------------------------------

    @staticmethod
    def is_free_text(value: str) -> bool:
        """Похоже ли значение на свободный текст, где имеет смысл NER."""
        if len(value) < MIN_TEXT_LEN:
            return False
        if not _HAS_SPACE.search(value):
            return False
        return bool(_CYRILLIC.search(value))

    def analyze(self, text: str) -> Set[str]:
        """Возвращает подмножество {'ner_person', 'ner_location'}."""
        if not self.is_free_text(text) or not self._load():
            return set()

        from natasha import Doc  # импорт здесь: в slim-образе natasha нет

        try:
            doc = Doc(text[:MAX_TEXT_LEN])
            doc.segment(self._segmenter)
            doc.tag_ner(self._tagger)
        except Exception as exc:  # noqa: BLE001
            log.debug("NER не смог разобрать значение: %s", exc)
            return set()

        self.calls += 1
        found: Set[str] = set()
        for span in doc.spans:
            if span.type == "PER":
                found.add("ner_person")
            elif span.type == "LOC":
                found.add("ner_location")
        return found
