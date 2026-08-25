# -*- coding: utf-8 -*-
"""Командный интерфейс."""
from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import List

from . import __version__
from .config import AppConfig, ConfigError, find_default_config, load_config
from .report import console, jsonout, markdown, xlsx
from .progress import active as active_bar
from .scanner import Scanner
from .sources.base import ReadWriteAccessError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_ACCESS = 3

FORMATS = ("summary", "detailed", "json", "xlsx")

log = logging.getLogger("pii_scan")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-scan",
        description="Поиск персональных данных (152-ФЗ) в MySQL и ClickHouse.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  pii-scan --config /config/config.yml --dry-run\n"
            "  pii-scan --config /config/config.yml --limit 1000 --out /out\n"
            "  pii-scan --config /config/config.yml --only prod-mysql --no-ner\n"
        ),
    )
    parser.add_argument("--config", "-c", help="путь к YAML-конфигу")
    parser.add_argument("--out", "-o", default=os.environ.get("PII_OUT", "/out"),
                        help="каталог для отчётов (по умолчанию /out)")
    parser.add_argument("--formats", default="all",
                        help="через запятую: " + ", ".join(FORMATS) + " или all")
    parser.add_argument("--dry-run", action="store_true",
                        help="только инвентаризация схемы, значения не читаются")
    parser.add_argument("--limit", type=int,
                        help="строк выборки на таблицу (переопределяет конфиг)")
    parser.add_argument("--strategy", choices=("head", "tail", "head_tail"),
                        help="откуда брать выборку: head — начало таблицы, "
                             "tail — конец, head_tail — пополам (по умолчанию)")
    parser.add_argument("--only", action="append", metavar="ИСТОЧНИК",
                        help="сканировать только указанный источник (можно "
                             "повторять)")
    parser.add_argument("--no-ner", action="store_true",
                        help="отключить NER по свободному тексту")
    parser.add_argument("--no-json", action="store_true",
                        help="не разбирать JSON внутри значений")
    throttle = parser.add_argument_group("ограничение нагрузки")
    throttle.add_argument("--pause-ms", type=int, metavar="МС",
                          help="пауза между запросами к БД")
    throttle.add_argument("--max-qpm", type=int, metavar="N",
                          help="не больше N запросов в минуту")
    throttle.add_argument("--max-minutes", type=int, metavar="МИН",
                          help="бюджет времени: по исчерпании прогон корректно "
                               "завершается и сохраняет найденное")
    throttle.add_argument("--no-grouping", action="store_true",
                          help="не наследовать результат на однотипные "
                               "таблицы (шарды, помесячные партиции)")

    parser.add_argument("--allow-rw", action="store_true",
                        help="разрешить работу под учётной записью с правами "
                             "на запись (по умолчанию запуск блокируется)")
    parser.add_argument("--examples", metavar="N", type=int, nargs="?",
                        const=3,
                        help="показывать N замаскированных примеров значений "
                             "(по умолчанию не показывать; без числа — 3)")
    parser.add_argument("--show-values", action="store_true",
                        help="не маскировать примеры значений в отчётах "
                             "(отчёт станет носителем ПДн!)")
    parser.add_argument("--list-detectors", action="store_true",
                        help="показать доступные категории и правила и выйти")
    parser.add_argument("--detectors", metavar="СПИСОК",
                        help="какие категории ПДн искать, через запятую, "
                             "например names,contacts. По умолчанию все; "
                             "перечень — --list-detectors")
    parser.add_argument("--full-inventory", action="store_true",
                        help="в отчёты попадут все поля всех таблиц, включая "
                             "те, где ПДн не найдены — полная опись")
    parser.add_argument("--details", "-d", action="store_true",
                        help="вывести разбивку по полям: какое ПДн в каком "
                             "поле и на каком основании")
    parser.add_argument("--progress", choices=("auto", "on", "off"),
                        help="индикатор выполнения: auto — только в терминале "
                             "(по умолчанию), on — всегда, off — никогда")
    parser.add_argument("-q", "--quiet", action="store_true", help="только ошибки")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный лог")
    parser.add_argument("--version", action="version",
                        version=f"pii-scan {__version__}")
    return parser


class ProgressAwareHandler(logging.StreamHandler):
    """Стирает полосу прогресса перед строкой лога и рисует её заново."""

    def emit(self, record: logging.LogRecord) -> None:
        bar = active_bar()
        if bar is not None:
            bar.clear()
        super().emit(record)
        if bar is not None:
            bar.redraw()


def setup_logging(args: argparse.Namespace) -> None:
    level = logging.INFO
    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    handler = ProgressAwareHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S"))
    logging.basicConfig(level=level, handlers=[handler])
    if not args.verbose:
        # Драйверы печатают полный traceback на каждую ошибку подключения.
        # Свою причину мы и так покажем одной строкой.
        for noisy in ("clickhouse_connect", "urllib3", "pymysql"):
            logging.getLogger(noisy).setLevel(logging.CRITICAL)


def check_out_dir(path: str) -> None:
    """Права на каталог отчётов проверяются ДО сканирования.

    Иначе многочасовой прогон по проду завершится потерей результата на
    последнем шаге. Типовая причина — контейнер работает под своим uid,
    а смонтированный каталог принадлежит пользователю хоста.
    """
    probe = os.path.join(path, ".pii-scan-write-test")
    try:
        os.makedirs(path, exist_ok=True)
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.unlink(probe)
    except OSError as exc:
        raise ConfigError(
            f"каталог отчётов '{path}' недоступен для записи: {exc}.\n"
            f"В Docker запустите контейнер под своим пользователем:\n"
            f"  docker run --user \"$(id -u):$(id -g)\" …\n"
            f"либо выдайте права на каталог: chown 10001:10001 out"
        ) from exc


def resolve_formats(value: str) -> List[str]:
    if value.strip().lower() == "all":
        return list(FORMATS)
    chosen = [f.strip().lower() for f in value.split(",") if f.strip()]
    unknown = [f for f in chosen if f not in FORMATS]
    if unknown:
        raise ConfigError(f"неизвестные форматы отчёта: {', '.join(unknown)}")
    return chosen


def apply_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    if args.limit is not None:
        config.scan.sample_limit = args.limit
    if args.strategy:
        config.scan.sample_strategy = args.strategy
    if args.progress:
        config.scan.progress = args.progress
    if args.dry_run:
        config.scan.dry_run = True
    if args.no_ner:
        config.scan.ner = False
    if args.no_json:
        config.scan.scan_json = False
    if args.allow_rw:
        config.scan.allow_rw = True
    if args.examples is not None:
        config.scan.examples_per_hit = max(0, args.examples)
    if args.show_values:
        config.scan.show_values = True
        if config.scan.examples_per_hit <= 0:
            # Просить незамаскированные примеры и не просить примеров —
            # противоречие; выбираем то, что человек имел в виду.
            config.scan.examples_per_hit = 3
    if args.full_inventory:
        config.scan.full_inventory = True
    if args.detectors:
        config.scan.detectors = [
            part.strip() for part in args.detectors.split(",") if part.strip()
        ]
        from .detectors import resolve_detectors
        try:
            resolve_detectors(config.scan.detectors)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    if args.pause_ms is not None:
        config.throttle.pause_ms = args.pause_ms
    if args.max_qpm is not None:
        config.throttle.max_queries_per_minute = args.max_qpm
    if args.max_minutes is not None:
        config.throttle.max_duration_min = args.max_minutes
    if args.no_grouping:
        config.scan.group_similar_tables = False
    if args.only:
        wanted = set(args.only)
        known = {s.name for s in config.sources}
        missing = wanted - known
        if missing:
            raise ConfigError(
                f"источники не найдены в конфиге: {', '.join(sorted(missing))}; "
                f"доступны: {', '.join(sorted(known))}"
            )
        config.sources = [s for s in config.sources if s.name in wanted]
    return config


def write_reports(result, out_dir: str, formats: List[str]) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    writers = [
        ("summary", "summary.md", markdown.write_summary),
        ("detailed", "detailed.md", markdown.write_detailed),
        ("json", "findings.json", jsonout.write_json),
        ("xlsx", "registry.xlsx", xlsx.write_xlsx),
    ]
    written: List[str] = []
    for fmt, filename, writer in writers:
        if fmt not in formats:
            continue
        path = os.path.join(out_dir, filename)
        try:
            writer(result, path)
            written.append(path)
        except (OSError, RuntimeError) as exc:
            # Один не сформировавшийся отчёт не должен обнулять весь прогон
            log.error("Отчёт %s не сформирован: %s", filename, exc)
    return written


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    if args.list_detectors:
        from .detectors import render_detector_list
        print(render_detector_list())
        return EXIT_OK

    try:
        formats = resolve_formats(args.formats)
        path = args.config or find_default_config()
        if not path:
            raise ConfigError(
                "конфиг не найден: укажите --config или положите config.yml "
                "рядом (в контейнере — /config/config.yml)"
            )
        config = apply_overrides(load_config(path), args)
        check_out_dir(args.out)
    except ConfigError as exc:
        log.error("Ошибка конфигурации: %s", exc)
        return EXIT_CONFIG

    if config.scan.show_values:
        log.warning("Включён --show-values: отчёты будут содержать реальные "
                    "значения и сами станут носителями ПДн")

    log.info("Конфиг: %s | источников: %d | режим: %s", path, len(config.sources),
             "инвентаризация схемы" if config.scan.dry_run else "выборка значений")
    throttle = config.throttle
    if throttle.pause_ms or throttle.max_queries_per_minute or             throttle.max_duration_min:
        log.info("Ограничение нагрузки: пауза %d мс | не более %s запр./мин | "
                 "бюджет %s мин", throttle.pause_ms,
                 throttle.max_queries_per_minute or "∞",
                 throttle.max_duration_min or "∞")

    try:
        result = Scanner(config).run()
    except ReadWriteAccessError as exc:
        log.error("Запуск заблокирован: %s", exc)
        return EXIT_ACCESS
    except KeyboardInterrupt:
        log.error("Прервано пользователем")
        return EXIT_ERROR

    console.print_result(result, details=args.details)

    written = write_reports(result, args.out, formats)
    if written:
        log.info("Отчёты записаны:")
        for item in written:
            log.info("  %s", item)

    return EXIT_ERROR if result.errors else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
