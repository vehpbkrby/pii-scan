# -*- coding: utf-8 -*-
"""Каталог детекторов персональных данных (РФ).

Три независимых канала свидетельств:
  1) имя колонки / комментарий к ней   -> Detector.name_re
  2) значения из выборки               -> Detector.value_re + validator
  3) NER по свободному тексту          -> Detector.external (заполняет scanner)

Для структурных идентификаторов (СНИЛС, ИНН, полис ОМС, карта) обязательна
проверка контрольной суммы: без неё любая колонка с 10-значными числами
превращается в «ИНН».

Модуль не делает ввод-вывод и ни от чего не зависит — тестируется отдельно.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern, Sequence, Set

# --- категории ПДн по 152-ФЗ ------------------------------------------------

CAT_COMMON = "иные"
CAT_SPECIAL = "специальные"

CATEGORY_ORDER = [CAT_SPECIAL, CAT_COMMON]

# Значения длиннее обрезаются перед прогоном regex.
MAX_VALUE_SCAN_LEN = 4096


# --- контрольные суммы ------------------------------------------------------

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def valid_snils(value: str) -> bool:
    """СНИЛС: 9 значащих цифр + 2 контрольные."""
    d = _digits(value)
    if len(d) != 11:
        return False
    if len(set(d[:9])) == 1:  # 000000000, 111111111 — тестовый мусор
        return False
    total = sum(int(d[i]) * (9 - i) for i in range(9))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check in (100, 101):
            check = 0
    return check == int(d[9:])


def valid_inn(value: str) -> bool:
    """ИНН: 10 цифр (юрлицо) или 12 цифр (физлицо/ИП)."""
    d = _digits(value)
    if len(set(d)) == 1:  # 0000000000 формально проходит контроль, но это мусор
        return False
    if len(d) == 10:
        coef = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        n = sum(int(d[i]) * coef[i] for i in range(9)) % 11 % 10
        return n == int(d[9])
    if len(d) == 12:
        c1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        c2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        n1 = sum(int(d[i]) * c1[i] for i in range(10)) % 11 % 10
        n2 = sum(int(d[i]) * c2[i] for i in range(11)) % 11 % 10
        return n1 == int(d[10]) and n2 == int(d[11])
    return False


def valid_luhn(value: str, length: Optional[int] = None) -> bool:
    """Алгоритм Луна: банковские карты (13–19 цифр), единый полис ОМС (16)."""
    d = _digits(value)
    if length is not None:
        if len(d) != length:
            return False
    elif not 13 <= len(d) <= 19:
        return False
    if len(set(d)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def valid_oms(value: str) -> bool:
    """Единый номер полиса ОМС: 16 цифр, контроль по Луну."""
    return valid_luhn(value, length=16)


def valid_phone_ru(value: str) -> bool:
    d = _digits(value)
    if len(d) == 11 and d[0] in "78":
        d = d[1:]
    elif len(d) != 10:
        return False
    if len(set(d)) == 1:
        return False
    return d[0] in "3489"  # мобильные и коды регионов


def valid_passport_rf(value: str) -> bool:
    """Серия+номер паспорта РФ. Контрольной суммы нет, отсекаем явный мусор."""
    d = _digits(value)
    if len(d) != 10:
        return False
    if len(set(d)) == 1:
        return False
    series = d[:4]
    return series != "0000" and d[4:] != "000000"


# --- ФИО --------------------------------------------------------------------

_PATRONYMIC = re.compile(
    r"(ович|евич|ьевич|иевич|овна|евна|ьевна|иевна|ична|инична|оглы|кызы)$", re.I
)
# Осторожно с окончаниями: -ый/-ий/-ая дают ложные срабатывания на обычных
# прилагательных («Красный Квадрат»), поэтому оставлены только -ский/-цкий.
_SURNAME = re.compile(
    r"(ов|ев|ёв|ин|ын|ова|ева|ёва|ина|ына|ский|цкий|ская|цкая|ко|ук|юк|"
    r"швили|дзе|ян|енко|чук)$",
    re.I,
)
_CYR_WORD = re.compile(r"^[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?$")
_WORD = r"[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?"
_INITIAL = r"[А-ЯЁ]\.?"
# Инициалы бывают и до фамилии, и после: «Иванов И.И.», «И.И. Иванов»,
# «И. Иванов», «Иванов И». Ловим оба порядка.
_FIO_INITIALS = re.compile(
    rf"^(?:{_WORD}\s*{_INITIAL}(?:\s*{_INITIAL})?"
    rf"|{_INITIAL}(?:\s*{_INITIAL})?\s*{_WORD})$"
)


def looks_like_fio(value: str) -> bool:
    """'Иванов Иван Иванович', 'Иванов И.И.' — ФИО целиком."""
    v = " ".join(value.split())
    if not 5 <= len(v) <= 80:
        return False
    if _FIO_INITIALS.match(v):
        return True
    tokens = v.split()
    if not 2 <= len(tokens) <= 4:
        return False
    if not all(_CYR_WORD.match(t) for t in tokens):
        return False
    return any(_PATRONYMIC.search(t) for t in tokens) or any(
        _SURNAME.search(t) for t in tokens
    )


def looks_like_name_part(value: str) -> bool:
    """Одиночная часть имени. Осмысленно только для колонок с говорящим именем."""
    v = value.strip()
    return bool(1 < len(v) <= 40) and bool(_CYR_WORD.match(v))


_DATE_RE = re.compile(
    r"\b(?:(?P<y1>(?:19|20)\d{2})[-./](?P<m1>\d{1,2})[-./](?P<d1>\d{1,2})"
    r"|(?P<d2>\d{1,2})[-./](?P<m2>\d{1,2})[-./](?P<y2>(?:19|20)\d{2}))\b"
)


def looks_like_birth_date(value: str) -> bool:
    m = _DATE_RE.search(value)
    if not m:
        return False
    year = int(m.group("y1") or m.group("y2"))
    month = int(m.group("m1") or m.group("m2"))
    day = int(m.group("d1") or m.group("d2"))
    return 1900 <= year <= 2020 and 1 <= month <= 12 and 1 <= day <= 31


# --- описание детектора -----------------------------------------------------

@dataclass(frozen=True)
class Detector:
    code: str
    title: str
    category: str
    name_re: Optional[Pattern] = None
    value_re: Optional[Pattern] = None
    validator: Optional[Callable[[str], bool]] = None
    weight: float = 1.0          # вклад совпадения значений в уверенность
    name_only: bool = False      # определяется только по имени колонки
    whole_value: bool = False    # validator применяется ко всему значению
    external: bool = False       # заполняется извне (NER), не regex
    third_party: bool = False    # ПДн третьих лиц (родственники и т.п.)
    presence_based: bool = False # важен факт наличия, а не доля значений

    def matches_value(self, value: str) -> bool:
        if self.name_only or self.external:
            return False
        v = value[:MAX_VALUE_SCAN_LEN]
        if self.whole_value:
            if self.validator is not None:
                return self.validator(v)
            return bool(self.value_re and self.value_re.fullmatch(v.strip()))
        if self.value_re is None:
            return False
        for m in self.value_re.finditer(v):
            if self.validator is None or self.validator(m.group(0)):
                return True
        return False

    def matches_name(self, name: str, comment: str = "") -> bool:
        """Ищет по имени поля и комментарию к нему.

        Имя проверяется в двух видах — как есть и с подчёркиваниями,
        заменёнными на пробелы. Иначе `\\bfio\\b` не сработает на `client_fio`:
        для регулярных выражений подчёркивание — символ слова, и границы
        слова там нет. А это самое обычное именование полей.
        """
        if self.name_re is None:
            return False
        low = name.lower()
        haystack = f"{low} {low.replace('_', ' ')} {comment.lower()}"
        return bool(self.name_re.search(haystack))


# Поля, где по смыслу лежит человек, но слова «фамилия» в названии нет:
# rp_responsible, executor, менеджер, куратор. Без них одиночные фамилии
# в таких колонках пропускались.
ROLE_RE = (r"|отв\\b|ответствен|исполнител|responsible|manager|менеджер|\\bagent\\b|агент|сотрудник|работник|employee|автор|author|owner|владелец|куратор|curator|руководител|получател|представител|контактн.*лиц|\\bперсона\\b")


def _n(pattern: str) -> Pattern:
    return re.compile(pattern, re.I | re.U)


# --- каталог ----------------------------------------------------------------
# Блок A — идентификаторы с контрольной суммой (ложных срабатываний почти нет)

_A = [
    Detector(
        code="snils",
        title="СНИЛС",
        category=CAT_COMMON,
        name_re=_n(r"снилс|snils|\bпфр\b|страх.*свид|insurance_?number"),
        value_re=re.compile(r"\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{2}\b"),
        validator=valid_snils,
        weight=1.0,
    ),
    Detector(
        code="inn",
        title="ИНН",
        category=CAT_COMMON,
        name_re=_n(r"\binn\b|инн|taxpayer|tax_?id|налог"),
        value_re=re.compile(r"\b\d{10}\b|\b\d{12}\b"),
        validator=valid_inn,
        weight=0.9,
    ),
    Detector(
        code="oms",
        title="полис ОМС (ЕНП)",
        category=CAT_COMMON,
        name_re=_n(r"полис|\boms\b|\bомс\b|\bенп\b|medical_?policy"),
        value_re=re.compile(r"\b\d{16}\b"),
        validator=valid_oms,
        weight=0.85,
    ),
    Detector(
        code="bank_card",
        title="номер банковской карты",
        category=CAT_COMMON,
        name_re=_n(r"card_?(no|num|number|pan)|\bpan\b|карт[аы]|credit_?card"),
        value_re=re.compile(r"\b(?:\d[ \-]?){12,18}\d\b"),
        validator=valid_luhn,
        weight=1.0,
    ),
]

# Блок B — документы без контрольной суммы: вес занижен, нужен второй сигнал

_B = [
    Detector(
        code="passport_rf",
        title="паспорт РФ (серия и номер)",
        category=CAT_COMMON,
        name_re=_n(r"passport|паспорт|pasport|серия.*номер|doc_?serial|"
                   r"документ.*(сери|номер)"),
        value_re=re.compile(r"\b\d{2}\s?\d{2}\s?[\-\s]?\d{6}\b"),
        validator=valid_passport_rf,
        weight=0.45,
    ),
    Detector(
        code="foreign_passport",
        title="заграничный паспорт",
        category=CAT_COMMON,
        name_re=_n(r"загран|foreign_?passport|international_?passport"),
        value_re=re.compile(r"\b\d{2}\s?\d{7}\b"),
        weight=0.45,
    ),
    Detector(
        code="driver_license",
        title="водительское удостоверение",
        category=CAT_COMMON,
        name_re=_n(r"driver_?lic|водит.*удост|\bву\b|\bvu_?(num|no)\b|prava"),
        value_re=re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b"),
        weight=0.45,
    ),
    Detector(
        code="birth_certificate",
        title="свидетельство о рождении",
        category=CAT_COMMON,
        name_re=_n(r"свид.*рожд|birth_?cert|акт.*запис.*рожд"),
        name_only=True,
    ),
    Detector(
        code="bank_account",
        title="номер банковского счёта",
        category=CAT_COMMON,
        name_re=_n(r"account_?(no|num|number)|\bсч[её]т|расч.*сч|\bбик\b|"
                   r"\bbic\b|iban"),
        value_re=re.compile(r"\b\d{20}\b"),
        weight=0.45,
    ),
]

# Блок C — контактные данные

_C = [
    Detector(
        code="email",
        title="адрес электронной почты",
        category=CAT_COMMON,
        name_re=_n(r"e?_?mail|почт|email"),
        value_re=re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        weight=1.0,
    ),
    Detector(
        code="phone",
        title="номер телефона",
        category=CAT_COMMON,
        name_re=_n(r"phone|\btel\b|telefon|телефон|\bмоб\b|mobile|номер_?тел|"
                   r"msisdn|контакт"),
        value_re=re.compile(
            r"(?:\+7|\b8|\b7)[\s\-(]*\d{3}[\s\-)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}\b"
        ),
        validator=valid_phone_ru,
        weight=1.0,
    ),
    Detector(
        code="address",
        title="адрес",
        category=CAT_COMMON,
        name_re=_n(r"address|адрес|adres|street|улиц|город|\bcity\b|прописк|"
                   r"регистрац.*адрес|проживан"),
        value_re=re.compile(
            r"(?:\b(?:ул|улица|просп|пр-?кт|проезд|пер|бул|наб|ш\.|шоссе|г\.|"
            r"город|обл|область|пос|село|дер|мкр|корп|стр|кв|д)\.?\s*)"
            r"[^\s,;]{1,40}",
            re.I,
        ),
        weight=0.6,
    ),
    Detector(
        code="postal_code",
        title="почтовый индекс",
        category=CAT_COMMON,
        name_re=_n(r"индекс|zip|postal|postcode"),
        value_re=re.compile(r"\b[1-6]\d{5}\b"),
        weight=0.3,   # шестизначных чисел много, вес намеренно низкий
    ),
]

# Блок D — имя

_D = [
    Detector(
        code="fio",
        title="ФИО",
        category=CAT_COMMON,
        name_re=_n(r"\bfio\b|фио|full_?name|fullname|\bname\b|клиент.*имя|"
                   r"client_?name|customer_?name|\bfrom_?name\b" + ROLE_RE),
        validator=looks_like_fio,
        whole_value=True,
        weight=1.0,
    ),
    Detector(
        code="name_part",
        title="часть имени (фамилия / имя / отчество)",
        category=CAT_COMMON,
        name_re=_n(r"фамил|surname|last_?name|first_?name|\bимя\b|отчеств|"
                   r"patronymic|middle_?name|familiya|imya|otchestvo" + ROLE_RE),
        validator=looks_like_name_part,
        whole_value=True,
        # Одиночное слово с заглавной буквы бывает и фамилией, и городом
        # (Ростов, Псков, Киров). Веса хватает на «требует проверки»:
        # колонка не теряется, но и в ПДн без второго признака не идёт.
        weight=0.5,
    ),
    Detector(
        code="ner_person",
        title="ФИО в свободном тексте (NER)",
        category=CAT_COMMON,
        external=True,
        presence_based=True,
        weight=0.9,
    ),
    Detector(
        code="ner_location",
        title="адрес / населённый пункт в свободном тексте (NER)",
        category=CAT_COMMON,
        external=True,
        presence_based=True,
        weight=0.45,
    ),
]

# Блок E — рождение

_E = [
    Detector(
        code="birth_date",
        title="дата рождения",
        category=CAT_COMMON,
        name_re=_n(r"birth|\bdob\b|рожд|дата_?рожд|birthday|date_?of_?birth|"
                   r"data_?rozhd"),
        validator=looks_like_birth_date,
        whole_value=True,
        weight=0.5,
    ),
    Detector(
        code="birth_place",
        title="место рождения",
        category=CAT_COMMON,
        name_re=_n(r"мест.*рожд|birth_?place|place_?of_?birth|уроженец|"
                   r"mesto_?rozhd"),
        name_only=True,
    ),
]

# Блок F — специальные категории (ст. 10 152-ФЗ), только по именам колонок

_F = [
    Detector(
        code="health",
        title="сведения о состоянии здоровья",
        category=CAT_SPECIAL,
        name_re=_n(r"диагноз|diagnos|\bмкб\b|\bicd\b|болезн|health|здоров|"
                   r"инвалид|disabilit|наркол|психиатр|беремен|med_?record|"
                   r"мед_?карт|анамнез|госпитал|прививк|vaccin|аллерг|"
                   r"группа_?кров|blood_?type"),
        name_only=True,
    ),
    Detector(
        code="special_other",
        title="спецкатегория: национальность, раса, религия, взгляды, судимость",
        category=CAT_SPECIAL,
        name_re=_n(r"национальн|nationality|этнич|ethnic|вероисповед|религ|"
                   r"religion|политич|political|судим|criminal_?record|"
                   r"интимн|\bраса\b|\brace\b|профсоюз|trade_?union"),
        name_only=True,
    ),
]

# Блок «родственники» — ПДн третьих лиц, по ним обычно нет согласия

_R = [
    Detector(
        code="relatives",
        title="сведения о родственниках (ПДн третьих лиц)",
        category=CAT_COMMON,
        name_re=_n(r"родствен|супруг|\bжена\b|\bмуж\b|\bдети\b|\bдетей\b|"
                   r"ребен|ребён|child|kids|иждивен|dependent|relative|"
                   r"\bkin\b|spouse|emergency_?contact|контакт.*экстрен|"
                   r"\bмать\b|\bотец\b|родител|parent|опекун|guardian"),
        name_only=True,
        third_party=True,
    ),
]

DETECTORS: List[Detector] = _A + _B + _C + _D + _E + _F + _R
DETECTORS_BY_CODE: Dict[str, Detector] = {d.code: d for d in DETECTORS}

# Детекторы, работающие по значениям — прогоняются на каждой строке выборки.
VALUE_DETECTORS: List[Detector] = [
    d for d in DETECTORS if not d.name_only and not d.external
]

NER_CODES = ("ner_person", "ner_location")


# Группы для настройки: перечислять коды по одному неудобно, а «искать только
# ФИО» — обычное требование. Названия принимаются и русские, и латиницей.
DETECTOR_GROUPS: Dict[str, List[str]] = {
    "фио": ["fio", "name_part", "ner_person"],
    "контакты": ["email", "phone", "address", "postal_code", "ner_location"],
    "документы": ["snils", "inn", "oms", "passport_rf", "foreign_passport",
                  "driver_license", "birth_certificate"],
    "финансы": ["bank_card", "bank_account"],
    "рождение": ["birth_date", "birth_place"],
    "спецкатегории": ["health", "special_other"],
    "родственники": ["relatives"],
}

_GROUP_ALIASES = {
    "fio": "фио", "name": "фио", "names": "фио",
    "contacts": "контакты", "contact": "контакты",
    "documents": "документы", "docs": "документы",
    "finance": "финансы", "financial": "финансы",
    "birth": "рождение",
    "special": "спецкатегории",
    "relatives": "родственники", "family": "родственники",
}


def known_detector_names() -> List[str]:
    """Всё, что можно указать в настройке: группы и отдельные коды."""
    return sorted(DETECTOR_GROUPS) + sorted(DETECTORS_BY_CODE)


def resolve_detectors(names: Sequence[str]) -> Set[str]:
    """Разворачивает список групп и кодов в набор кодов детекторов.

    Пустой список означает «искать всё» — так по умолчанию.
    """
    if not names:
        return set(DETECTORS_BY_CODE)

    active: Set[str] = set()
    unknown: List[str] = []
    for raw in names:
        key = str(raw).strip().lower()
        key = _GROUP_ALIASES.get(key, key)
        if key in DETECTOR_GROUPS:
            active.update(DETECTOR_GROUPS[key])
        elif key in DETECTORS_BY_CODE:
            active.add(key)
        else:
            unknown.append(str(raw))
    if unknown:
        raise ValueError(
            f"неизвестные категории: {', '.join(unknown)}. "
            f"Доступно: {', '.join(known_detector_names())}"
        )
    return active


def describe_detectors(active: Set[str]) -> str:
    """Человеческое описание охвата — попадает в шапку отчёта."""
    if active >= set(DETECTORS_BY_CODE):
        return "все категории"
    groups = [
        name for name, codes in DETECTOR_GROUPS.items()
        if set(codes) & active
    ]
    covered = {c for name in groups for c in DETECTOR_GROUPS[name]}
    extra = sorted(
        DETECTORS_BY_CODE[c].title for c in active - covered
        if c in DETECTORS_BY_CODE
    )
    parts = [
        name if set(DETECTOR_GROUPS[name]) <= active else f"{name} (частично)"
        for name in groups
    ]
    return ", ".join(parts + extra) or "ничего не выбрано"


def detect_in_value(value: str, active: Optional[Set[str]] = None) -> Set[str]:
    """Коды детекторов, сработавших на конкретном значении."""
    return {
        d.code for d in VALUE_DETECTORS
        if (active is None or d.code in active) and d.matches_value(value)
    }


def detect_in_column_name(name: str, comment: str = "",
                          active: Optional[Set[str]] = None) -> Set[str]:
    """Коды детекторов, сработавших на имени колонки или комментарии."""
    return {
        d.code for d in DETECTORS
        if (active is None or d.code in active) and d.matches_name(name, comment)
    }


def mask_value(value: str, keep_head: int = 2, keep_tail: int = 1) -> str:
    """Маскирование для отчёта: сами ПДн в отчёт попадать не должны."""
    v = " ".join(str(value).split())
    if len(v) > 48:
        v = v[:48] + "…"
    if len(v) <= keep_head + keep_tail:
        return "*" * len(v)
    return v[:keep_head] + "*" * (len(v) - keep_head - keep_tail) + v[-keep_tail:]
