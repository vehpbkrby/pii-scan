# -*- coding: utf-8 -*-
"""Адаптеры источников данных."""

from .base import Source, SourceError, ReadWriteAccessError, build_source

__all__ = ["Source", "SourceError", "ReadWriteAccessError", "build_source"]
