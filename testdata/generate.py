# -*- coding: utf-8 -*-
"""Генератор синтетических данных для проверки сканера.

Создаёт два init-скрипта: для MySQL (база crm) и ClickHouse (база analytics).
Данные вымышленные, но структурно правдоподобные: валидные контрольные суммы
СНИЛС/ИНН/ОМС/карт, русские ФИО, адреса, JSON-полезная нагрузка, свободный
текст для NER.

Специально заложены ловушки на ложные срабатывания:
  * orders.order_code   — случайные 10-значные коды (часть проходит контроль ИНН);
  * app_settings        — технические настройки, ПДн быть не должно;
  * audit_log           — логины и IP: в охват не входят, шуметь не должны;
  * metrics             — числовые метрики без ПДн;
  * orders_mv           — материализованное представление, должно пропускаться.

Запуск:  python testdata/generate.py <каталог_для_sql>
"""
from __future__ import annotations

import json
import os
import random
import sys
from datetime import date, datetime, timedelta

SEED = 20260821
random.seed(SEED)

SURNAMES_M = ["Иванов", "Петров", "Смирнов", "Кузнецов", "Соколов", "Попов",
              "Лебедев", "Козлов", "Новиков", "Морозов", "Волков", "Зайцев",
              "Павлов", "Семенов", "Голубев", "Виноградов", "Богданов"]
SURNAMES_F = [s + "а" for s in SURNAMES_M]
NAMES_M = ["Иван", "Петр", "Алексей", "Дмитрий", "Сергей", "Андрей", "Михаил",
           "Николай", "Роман", "Артем", "Владимир", "Юрий"]
NAMES_F = ["Анна", "Мария", "Елена", "Ольга", "Татьяна", "Наталья", "Ирина",
           "Светлана", "Екатерина", "Юлия", "Марина"]
PATRONYMIC_M = ["Иванович", "Петрович", "Алексеевич", "Дмитриевич", "Сергеевич",
                "Андреевич", "Михайлович", "Николаевич"]
PATRONYMIC_F = ["Ивановна", "Петровна", "Алексеевна", "Дмитриевна", "Сергеевна",
                "Андреевна", "Михайловна", "Николаевна"]

CITIES = ["Москва", "Санкт-Петербург", "Новосибирск", "Екатеринбург", "Казань",
          "Нижний Новгород", "Челябинск", "Самара", "Омск", "Ростов-на-Дону"]
STREETS = ["Ленина", "Советская", "Мира", "Гагарина", "Пушкина", "Победы",
           "Лесная", "Центральная", "Молодежная", "Школьная"]

MAIL_DOMAINS = ["example.com", "mail.test", "corp.local", "post.example"]
POSITIONS = ["менеджер", "инженер", "бухгалтер", "аналитик", "кладовщик",
             "водитель", "оператор", "руководитель отдела"]
DIAGNOSES = ["ОРВИ", "Гипертония", "МКБ J06.9", "Хронический бронхит",
             "Аллергия сезонная", "", "", ""]
EVENTS = ["page_view", "add_to_cart", "checkout", "search", "login", "logout"]
METRICS = ["cpu_usage", "rps", "latency_ms", "queue_depth", "cache_hit_ratio"]
SETTINGS = ["smtp_host", "smtp_port", "session_ttl", "max_upload_mb",
            "feature_new_cart", "retry_count", "cache_ttl", "log_level"]


# --- идентификаторы с корректными контрольными суммами ----------------------

def gen_snils() -> str:
    while True:
        body = "".join(random.choice("0123456789") for _ in range(9))
        if len(set(body)) == 1:
            continue
        total = sum(int(body[i]) * (9 - i) for i in range(9))
        if total < 100:
            check = total
        elif total in (100, 101):
            check = 0
        else:
            check = total % 101
            check = 0 if check in (100, 101) else check
        return f"{body[:3]}-{body[3:6]}-{body[6:9]} {check:02d}"


def gen_inn12() -> str:
    body = [random.randint(0, 9) for _ in range(10)]
    c1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    c2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    d11 = sum(body[i] * c1[i] for i in range(10)) % 11 % 10
    body.append(d11)
    d12 = sum(body[i] * c2[i] for i in range(11)) % 11 % 10
    body.append(d12)
    return "".join(map(str, body))


def gen_luhn(prefix: str, length: int) -> str:
    body = prefix + "".join(random.choice("0123456789")
                            for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return body + str((10 - total % 10) % 10)


def gen_card() -> str:
    return gen_luhn(random.choice(["4", "5"]), 16)


def gen_oms() -> str:
    return gen_luhn("", 16)


def gen_phone() -> str:
    return f"+79{random.randint(10, 99)}{random.randint(1000000, 9999999)}"


def gen_passport() -> str:
    return f"{random.randint(10, 99)} {random.randint(10, 99)} " \
           f"{random.randint(100000, 999999)}"


def gen_person(gender: str = None):
    gender = gender or random.choice("mf")
    if gender == "m":
        return (random.choice(SURNAMES_M), random.choice(NAMES_M),
                random.choice(PATRONYMIC_M))
    return (random.choice(SURNAMES_F), random.choice(NAMES_F),
            random.choice(PATRONYMIC_F))


def gen_email(first: str, last: str) -> str:
    translit = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e",
                "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l",
                "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s",
                "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "c", "ч": "ch",
                "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e",
                "ю": "yu", "я": "ya", "ё": "e"}
    def tr(text):
        return "".join(translit.get(c, c) for c in text.lower())
    return f"{tr(first)[0]}.{tr(last)}{random.randint(1, 99)}@" \
           f"{random.choice(MAIL_DOMAINS)}"


def gen_address() -> str:
    return (f"г. {random.choice(CITIES)}, ул. {random.choice(STREETS)}, "
            f"д. {random.randint(1, 120)}, кв. {random.randint(1, 300)}")


def gen_birth_date() -> str:
    start = date(1955, 1, 1)
    return (start + timedelta(days=random.randint(0, 16000))).isoformat()


def gen_comment(fio_full: str) -> str:
    """30% комментариев содержат ПДн в свободном тексте — работа для NER."""
    neutral = ["Оплата картой при получении", "Самовывоз со склада",
               "Требуется упаковка в подарочную бумагу", "Позиция под заказ",
               "Согласовать дату отгрузки", "Клиент постоянный, скидка 5%"]
    with_pii = [
        f"Перезвонить {fio_full} после обеда",
        f"Доставка получателю {fio_full}, домофон не работает",
        f"Согласовано с {fio_full}",
        f"Клиент {fio_full.split()[1]} просил счет на оплату",
        f"Забрать в пункте выдачи в городе {random.choice(CITIES)}",
    ]
    return random.choice(with_pii) if random.random() < 0.3 \
        else random.choice(neutral)


# --- вспомогательное --------------------------------------------------------

def q(value) -> str:
    """Строковый литерал SQL. Апострофы в данных не используются намеренно."""
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "").replace("\\", "") + "'"


def batched_insert(table: str, columns, rows, batch: int = 500) -> str:
    out = []
    cols = ", ".join(columns)
    for i in range(0, len(rows), batch):
        values = ",\n".join("(" + ", ".join(r) + ")" for r in rows[i:i + batch])
        out.append(f"INSERT INTO {table} ({cols}) VALUES\n{values};")
    return "\n".join(out)


def ts(days_back: int = 400) -> str:
    moment = datetime(2026, 8, 1) - timedelta(
        seconds=random.randint(0, days_back * 86400))
    return moment.strftime("%Y-%m-%d %H:%M:%S")


# --- MySQL ------------------------------------------------------------------

def build_mysql(clients_n=800, orders_n=2000, employees_n=120,
                audit_n=1500) -> str:
    # SET NAMES обязателен: клиент mysql в docker-entrypoint читает дамп в
    # кодировке по умолчанию и кириллица уезжает в двойную кодировку
    parts = ["SET NAMES utf8mb4;",
             "CREATE DATABASE IF NOT EXISTS crm "
             "DEFAULT CHARACTER SET utf8mb4;", "USE crm;"]

    # 1. Клиенты — прямые идентификаторы, паспорт разнесён на две колонки
    parts.append("""
CREATE TABLE clients (
  id            INT PRIMARY KEY,
  last_name     VARCHAR(60),
  first_name    VARCHAR(60),
  middle_name   VARCHAR(60),
  email         VARCHAR(120),
  phone         VARCHAR(20),
  birth_date    DATE,
  passport_seria CHAR(4)  COMMENT 'Серия паспорта',
  passport_nomer CHAR(6)  COMMENT 'Номер паспорта',
  snils         VARCHAR(14),
  inn           VARCHAR(12),
  reg_address   VARCHAR(200),
  created_at    DATETIME
) ENGINE=InnoDB;""")
    clients = []
    for i in range(1, clients_n + 1):
        last, first, mid = gen_person()
        passport = gen_passport().replace(" ", "")
        clients.append([
            str(i), q(last), q(first), q(mid), q(gen_email(first, last)),
            q(gen_phone()), q(gen_birth_date()), q(passport[:4]), q(passport[4:]),
            q(gen_snils()), q(gen_inn12()), q(gen_address()), q(ts()),
        ])
    parts.append(batched_insert("clients", [
        "id", "last_name", "first_name", "middle_name", "email", "phone",
        "birth_date", "passport_seria", "passport_nomer", "snils", "inn",
        "reg_address", "created_at"], clients))

    # 2. Заказы — ловушка order_code + ПДн в свободном тексте и в JSON
    parts.append("""
CREATE TABLE orders (
  id          INT PRIMARY KEY,
  client_id   INT,
  order_code  CHAR(10),
  amount      DECIMAL(10,2),
  comment     TEXT,
  payload     JSON,
  created_at  DATETIME
) ENGINE=InnoDB;""")
    orders = []
    for i in range(1, orders_n + 1):
        last, first, mid = gen_person()
        fio = f"{last} {first} {mid}"
        payload = {
            "source": random.choice(["web", "mobile", "call-center"]),
            "client": {"fio": fio, "phone": gen_phone(),
                       "email": gen_email(first, last)},
            "delivery": {"city": random.choice(CITIES),
                         "zip": str(random.randint(100000, 699999))},
            "items": random.randint(1, 8),
        }
        orders.append([
            str(i), str(random.randint(1, clients_n)),
            q("".join(random.choice("0123456789") for _ in range(10))),
            f"{random.randint(100, 90000)}.{random.randint(0, 99):02d}",
            q(gen_comment(fio)),
            q(json.dumps(payload, ensure_ascii=False)), q(ts()),
        ])
    parts.append(batched_insert("orders", [
        "id", "client_id", "order_code", "amount", "comment", "payload",
        "created_at"], orders))

    # 3. Сотрудники — спецкатегории и данные третьих лиц
    parts.append("""
CREATE TABLE employees (
  id                 INT PRIMARY KEY,
  fio                VARCHAR(150),
  tab_number         VARCHAR(10),
  position           VARCHAR(80),
  salary             DECIMAL(10,2),
  passport           VARCHAR(20),
  diagnosis          VARCHAR(120),
  emergency_contact  VARCHAR(150),
  children_count     TINYINT,
  hired_at           DATE
) ENGINE=InnoDB;""")
    employees = []
    for i in range(1, employees_n + 1):
        last, first, mid = gen_person()
        rel_last, rel_first, rel_mid = gen_person("f")
        employees.append([
            str(i), q(f"{last} {first} {mid}"), q(f"{random.randint(1000, 9999)}"),
            q(random.choice(POSITIONS)),
            f"{random.randint(40000, 250000)}.00", q(gen_passport()),
            q(random.choice(DIAGNOSES)),
            q(f"{rel_last} {rel_first} {rel_mid}"),
            str(random.randint(0, 3)), q(gen_birth_date()),
        ])
    parts.append(batched_insert("employees", [
        "id", "fio", "tab_number", "position", "salary", "passport",
        "diagnosis", "emergency_contact", "children_count", "hired_at"],
        employees))

    # 4. Настройки — ПДн быть не должно
    parts.append("""
CREATE TABLE app_settings (
  id            INT PRIMARY KEY,
  setting_key   VARCHAR(60),
  setting_value VARCHAR(200),
  updated_at    DATETIME
) ENGINE=InnoDB;""")
    settings = [
        [str(i + 1), q(f"{key}_{i}"), q(random.choice(
            ["true", "false", "300", "smtp.internal", "info", "10"])), q(ts())]
        for i, key in enumerate(SETTINGS * 5)
    ]
    parts.append(batched_insert("app_settings", [
        "id", "setting_key", "setting_value", "updated_at"], settings))

    # 5. Журнал — логины и IP в охват не входят, шуметь не должны
    parts.append("""
CREATE TABLE audit_log (
  id        INT PRIMARY KEY,
  event_ts  DATETIME,
  user_login VARCHAR(40),
  ip_addr   VARCHAR(45),
  action    VARCHAR(60),
  object_id INT
) ENGINE=InnoDB;""")
    audit = [
        [str(i), q(ts(200)),
         q(f"user{random.randint(1, 60)}"),
         q(f"10.0.{random.randint(0, 20)}.{random.randint(1, 254)}"),
         q(random.choice(["login", "logout", "update", "view", "export"])),
         str(random.randint(1, 5000))]
        for i in range(1, audit_n + 1)
    ]
    parts.append(batched_insert("audit_log", [
        "id", "event_ts", "user_login", "ip_addr", "action", "object_id"],
        audit))

    # 6. Учётные записи: только чтение и — для проверки блокировки — с записью
    parts.append("""
CREATE USER IF NOT EXISTS 'pii_reader'@'%' IDENTIFIED BY 'ReadOnly_2026!';
GRANT SELECT ON *.* TO 'pii_reader'@'%';
CREATE USER IF NOT EXISTS 'app_rw'@'%' IDENTIFIED BY 'Writer_2026!';
GRANT SELECT, INSERT, UPDATE, DELETE ON crm.* TO 'app_rw'@'%';
FLUSH PRIVILEGES;""")
    return "\n\n".join(parts) + "\n"


# --- ClickHouse -------------------------------------------------------------

def build_clickhouse(events_n=5000, orders_n=3000, metrics_n=5000) -> str:
    parts = ["CREATE DATABASE IF NOT EXISTS analytics;"]

    # 1. События — ПДн внутри JSON-строки params
    parts.append("""
CREATE TABLE analytics.events (
  event_ts  DateTime,
  user_id   UInt64,
  event     String,
  params    String,
  url       String,
  user_agent String
) ENGINE = MergeTree ORDER BY (event_ts, user_id);""")
    events = []
    for _ in range(events_n):
        last, first, mid = gen_person()
        if random.random() < 0.4:
            params = {"fio": f"{last} {first} {mid}", "phone": gen_phone(),
                      "email": gen_email(first, last),
                      "promo": random.choice(["SALE10", "NY2026", ""])}
        else:
            params = {"page": random.randint(1, 40),
                      "ref": random.choice(["direct", "search", "ads"]),
                      "ab_group": random.choice(["A", "B"])}
        events.append([
            q(ts(300)), str(random.randint(1000, 99999)),
            q(random.choice(EVENTS)),
            q(json.dumps(params, ensure_ascii=False)),
            q(f"https://shop.example/{random.choice(['catalog', 'cart', 'item'])}"
              f"/{random.randint(1, 999)}"),
            q("Mozilla/5.0 (X11; Linux x86_64)"),
        ])
    parts.append(batched_insert("analytics.events", [
        "event_ts", "user_id", "event", "params", "url", "user_agent"], events))

    # 2. Витрина заказов — прямые идентификаторы, включая ОМС и карту
    parts.append("""
CREATE TABLE analytics.orders_flat (
  order_id     UInt64,
  order_dt     DateTime,
  client_fio   String,
  client_phone String,
  client_email String,
  oms_polis    String,
  card_pan     String,
  amount       Decimal(12,2),
  city         String
) ENGINE = MergeTree ORDER BY order_id;""")
    orders = []
    for i in range(1, orders_n + 1):
        last, first, mid = gen_person()
        orders.append([
            str(i), q(ts(300)), q(f"{last} {first} {mid}"), q(gen_phone()),
            q(gen_email(first, last)), q(gen_oms()), q(gen_card()),
            f"{random.randint(100, 90000)}.00", q(random.choice(CITIES)),
        ])
    parts.append(batched_insert("analytics.orders_flat", [
        "order_id", "order_dt", "client_fio", "client_phone", "client_email",
        "oms_polis", "card_pan", "amount", "city"], orders))

    # 3. Метрики — ПДн быть не должно
    parts.append("""
CREATE TABLE analytics.metrics (
  metric_ts DateTime,
  metric    String,
  host      String,
  value     Float64
) ENGINE = MergeTree ORDER BY (metric_ts, metric);""")
    metrics = [
        [q(ts(90)), q(random.choice(METRICS)),
         q(f"node-{random.randint(1, 12)}"),
         f"{random.random() * 100:.3f}"]
        for _ in range(metrics_n)
    ]
    parts.append(batched_insert("analytics.metrics", [
        "metric_ts", "metric", "host", "value"], metrics))

    # 4. Материализованное представление — сканер должен его пропустить
    parts.append("""
CREATE MATERIALIZED VIEW analytics.orders_by_city
ENGINE = SummingMergeTree ORDER BY city
AS SELECT city, count() AS cnt FROM analytics.orders_flat GROUP BY city;""")

    # 5. Учётные записи
    parts.append("""
CREATE USER IF NOT EXISTS pii_reader IDENTIFIED WITH sha256_password
    BY 'ReadOnly_2026!' SETTINGS readonly = 2;
GRANT SELECT ON *.* TO pii_reader;
CREATE USER IF NOT EXISTS etl_writer IDENTIFIED WITH sha256_password
    BY 'Writer_2026!';
GRANT SELECT, INSERT ON analytics.* TO etl_writer;""")
    return "\n\n".join(parts) + "\n"


def main() -> None:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)
    for name, content in (("mysql_init.sql", build_mysql()),
                          ("clickhouse_init.sql", build_clickhouse())):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        print(f"{path}: {os.path.getsize(path) / 1024:.0f} КБ")


if __name__ == "__main__":
    main()
