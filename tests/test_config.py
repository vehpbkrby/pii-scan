# -*- coding: utf-8 -*-
"""Загрузка конфигурации: ошибки должны быть внятными, а не traceback."""
from __future__ import annotations

import pytest

from pii_scan.config import ConfigError, load_config

MINIMAL = """
sources:
  - name: db
    type: mysql
    host: 10.0.0.1
    user: pii_reader
    password: ${TEST_PWD}
"""


def write(tmp_path, text: str, name: str = "config.yml") -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_minimal_config(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PWD", "секрет")
    config = load_config(write(tmp_path, MINIMAL))
    assert len(config.sources) == 1
    source = config.sources[0]
    assert source.password == "секрет"
    assert source.port == 3306                    # порт по умолчанию
    assert "information_schema" in source.exclude_databases


def test_missing_file_is_reported_clearly(tmp_path):
    """Опечатка в пути — не повод показывать traceback."""
    with pytest.raises(ConfigError, match="не найден"):
        load_config(str(tmp_path / "нет-такого.yml"))


def test_broken_yaml_is_reported_clearly(tmp_path):
    with pytest.raises(ConfigError, match="некорректный YAML"):
        load_config(write(tmp_path, "sources: [\n  - name: db\n"))


def test_not_an_object(tmp_path):
    with pytest.raises(ConfigError, match="объектом верхнего уровня"):
        load_config(write(tmp_path, "- просто список\n"))


def test_missing_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_PWD", raising=False)
    with pytest.raises(ConfigError, match="TEST_PWD"):
        load_config(write(tmp_path, MINIMAL))


def test_env_var_default(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_PWD", raising=False)
    text = MINIMAL.replace("${TEST_PWD}", "${TEST_PWD:-пусто}")
    assert load_config(write(tmp_path, text)).sources[0].password == "пусто"


def test_unknown_option_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PWD", "x")
    text = "scan:\n  опечатка: 1\n" + MINIMAL
    with pytest.raises(ConfigError, match="неизвестные параметры"):
        load_config(write(tmp_path, text))


def test_unsupported_source_type(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PWD", "x")
    text = MINIMAL.replace("type: mysql", "type: oracle")
    with pytest.raises(ConfigError, match="не поддерживается"):
        load_config(write(tmp_path, text))


def test_duplicate_source_names(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PWD", "x")
    with pytest.raises(ConfigError, match="повторяющиеся"):
        load_config(write(tmp_path, MINIMAL + MINIMAL.split("sources:")[1]))


def test_bad_strategy_and_progress(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PWD", "x")
    with pytest.raises(ConfigError, match="sample_strategy"):
        load_config(write(tmp_path, "scan:\n  sample_strategy: середина\n" + MINIMAL))
    with pytest.raises(ConfigError, match="progress"):
        load_config(write(tmp_path, "scan:\n  progress: иногда\n" + MINIMAL))
