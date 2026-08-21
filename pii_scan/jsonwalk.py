# -*- coding: utf-8 -*-
"""Разбор JSON-значений: каждый ключ становится виртуальной колонкой.

В ClickHouse и в MySQL-полях типа json/text ПДн чаще всего лежат не в отдельной
колонке, а внутри payload. Поэтому значение вида
    {"client": {"phone": "+79161234567"}}
даёт путь `$.client.phone`, и в отчёте видно не только «в этой колонке есть
ПДн», но и где именно внутри структуры.
"""
from __future__ import annotations

import json
from typing import Iterator, Tuple

# Ограничители: JSON в логах бывает огромным и глубоко вложенным.
MAX_DEPTH = 6
MAX_NODES = 500
ARRAY_INDEX = "[*]"  # индексы массивов схлопываем, иначе путей будет тысячи


def looks_like_json(value: str) -> bool:
    v = value.lstrip()
    if not v or v[0] not in "{[":
        return False
    return v.rstrip()[-1] in "}]"


def parse(value: str):
    """Возвращает разобранный JSON или None, если это не JSON."""
    if not looks_like_json(value):
        return None
    try:
        data = json.loads(value)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, (dict, list)) else None


def walk(data, prefix: str = "$") -> Iterator[Tuple[str, str]]:
    """Обходит структуру, отдавая пары (путь, скалярное значение как строка)."""
    yield from _walk(data, prefix, depth=0, budget=[MAX_NODES])


def _walk(node, path: str, depth: int, budget) -> Iterator[Tuple[str, str]]:
    if budget[0] <= 0 or depth > MAX_DEPTH:
        return
    if isinstance(node, dict):
        for key, val in node.items():
            if budget[0] <= 0:
                return
            yield from _walk(val, f"{path}.{key}", depth + 1, budget)
    elif isinstance(node, list):
        for item in node:
            if budget[0] <= 0:
                return
            yield from _walk(item, f"{path}{ARRAY_INDEX}", depth + 1, budget)
    elif node is None or isinstance(node, bool):
        return
    else:
        budget[0] -= 1
        text = str(node).strip()
        if text:
            yield path, text


def leaf_name(path: str) -> str:
    """Последний ключ пути — по нему работают детекторы «по имени колонки»."""
    tail = path.rsplit(".", 1)[-1]
    return tail.replace(ARRAY_INDEX, "")
