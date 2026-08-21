# -*- coding: utf-8 -*-
"""Проверка правил распознавания. Значения ниже — синтетические."""
from __future__ import annotations

import pytest

from pii_scan.detectors import (
    detect_in_column_name,
    detect_in_value,
    looks_like_birth_date,
    looks_like_fio,
    mask_value,
    valid_inn,
    valid_luhn,
    valid_oms,
    valid_phone_ru,
    valid_snils,
)


# --- контрольные суммы ------------------------------------------------------

@pytest.mark.parametrize("value", ["112-233-445 95", "11223344595", "112 233 445 95"])
def test_snils_valid(value):
    assert valid_snils(value)


@pytest.mark.parametrize("value", [
    "112-233-445 96",   # неверная контрольная сумма
    "000-000-000 00",   # вырожденное значение
    "1122334459",       # не хватает цифры
])
def test_snils_invalid(value):
    assert not valid_snils(value)


@pytest.mark.parametrize("value", ["7707083893", "500102345600"])
def test_inn_valid(value):
    assert valid_inn(value)


@pytest.mark.parametrize("value", ["7707083894", "500102345601", "12345"])
def test_inn_invalid(value):
    assert not valid_inn(value)


def test_luhn():
    assert valid_luhn("4111 1111 1111 1111")
    assert not valid_luhn("4111 1111 1111 1112")
    assert not valid_luhn("1111111111111111")  # вырожденное


def test_oms_requires_16_digits():
    assert valid_oms("1234567890123452")
    assert not valid_oms("4111111111111")  # валиден по Луну, но не 16 цифр


def test_phone_ru():
    assert valid_phone_ru("+7 (916) 123-45-67")
    assert valid_phone_ru("89161234567")
    assert not valid_phone_ru("+7 (116) 123-45-67")  # код не бывает на 1
    assert not valid_phone_ru("1234")


# --- ФИО и даты -------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "Иванов Иван Иванович",
    "Петрова Анна Сергеевна",
    "Кузнецов И.И.",
    "Шевченко Олег",
])
def test_fio_positive(value):
    assert looks_like_fio(value)


@pytest.mark.parametrize("value", [
    "Красный Квадрат",       # нет суффиксов фамилии/отчества
    "ООО Ромашка",
    "иванов иван",           # без заглавных
    "Ivanov Ivan",
])
def test_fio_negative(value):
    assert not looks_like_fio(value)


def test_birth_date():
    assert looks_like_birth_date("15.03.1985")
    assert looks_like_birth_date("1985-03-15")
    assert not looks_like_birth_date("15.03.2024")  # позже верхней границы
    assert not looks_like_birth_date("просто текст")


# --- сквозные проверки ------------------------------------------------------

def test_detect_in_value():
    assert "email" in detect_in_value("написать на ivanov@example.com завтра")
    assert "snils" in detect_in_value("СНИЛС 112-233-445 95")
    assert "phone" in detect_in_value("тел. +7 916 123-45-67")
    assert "bank_card" in detect_in_value("4111 1111 1111 1111")


def test_technical_numbers_mostly_rejected():
    """Контрольная сумма отсекает подавляющее большинство технических чисел.

    Остаточная доля (для ИНН это ~1/11 случайных 10-значных чисел) гасится
    уже на уровне колонки: важна доля совпавших значений, а не единичное —
    см. tests/test_scanner.py::test_sequential_codes_are_not_pii.
    """
    assert not valid_inn("1234567890")
    assert not valid_inn("0000000000")
    assert not valid_snils("12345678901")
    assert "snils" not in detect_in_value("1234567890 0000000000")
    assert "inn" not in detect_in_value("1234567890 0000000000")


def test_detect_in_column_name():
    assert "snils" in detect_in_column_name("SNILS")
    assert "health" in detect_in_column_name("diagnosis_mkb10")
    assert "relatives" in detect_in_column_name("emergency_contact_phone")
    assert "name_part" in detect_in_column_name("last_name")
    assert detect_in_column_name("order_total") == set()


def test_underscore_is_a_word_separator():
    """client_fio, user_inn, ip_addr — подчёркивание не должно мешать."""
    assert "fio" in detect_in_column_name("client_fio")
    assert "fio" in detect_in_column_name("FIO_CLIENT")
    assert "inn" in detect_in_column_name("user_inn")
    assert "snils" in detect_in_column_name("employee_snils_number")
    # и привычные слитные написания по-прежнему работают
    assert "name_part" in detect_in_column_name("lastname")
    assert "name_part" in detect_in_column_name("last_name")


def test_column_comment_is_used():
    assert "passport_rf" in detect_in_column_name("f_17", "Серия и номер паспорта")


def test_mask_value():
    masked = mask_value("ivanov@example.com")
    assert masked.startswith("iv") and masked.endswith("m")
    assert "example" not in masked


# --- восстановление кодировки ----------------------------------------------

def test_repair_mojibake():
    from pii_scan.sources.base import repair_mojibake

    # 'Голубев', записанное через соединение с неверной кодировкой
    broken = "Голубев".encode("utf-8").decode("cp1252")
    assert repair_mojibake(broken) == "Голубев"

    # нормальные строки не трогаем
    assert repair_mojibake("Голубев") is None
    assert repair_mojibake("ivanov@example.com") is None
    assert repair_mojibake("112-233-445 95") is None
