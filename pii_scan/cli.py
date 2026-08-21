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
    parser.add_argument("--only", action="append", metavar="ИСТОЧНИК",
                        help="сканировать только указанный источник (можно "
                             "повторять)")
    parser.add_argument("--no-ner", action="store_true",
                        help="отключить NER по свободному тексту")
    parser.add_argument("--no-json", action="store_true",
                        help="не разбирать JSON внутри значений")
    parser.add_argument("--allow-rw", action="store_true",
                        help="разрешить работу под учётной записью с правами "
                             "на запись (по умолчанию запуск блокируется)")
    parser.add_argument("--show-values", action="store_true",
                        help="не маскировать примеры значений в отчётах "
                             "(отчёт станет носителем ПДн!)")
    parser.add_argument("-q", "--quiet", action="store_true", help="только ошибки")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный лог")
    parser.add_argument("--version", action="version",
                        version=f"pii-scan {__version__}")
    return parser


def setup_logging(args: argparse.Namespace) -> None:
    level = logging.INFO
    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    logging.basicConfig(
        level=level, stream=sys.stderr,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )


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
    if args.dry_run:
        config.scan.dry_run = True
    if args.no_ner:
        config.scan.ner = False
    if args.no_json:
        config.scan.scan_json = False
    if args.allow_rw:
        config.scan.allow_rw = True
    if args.show_values:
        config.scan.show_values = True
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
    written: List[str] = []
    if "summary" in formats:
        path = os.path.join(out_dir, "summary.md")
        markdown.write_summary(result, path)
        written.append(path)
    if "detailed" in formats:
        path = os.path.join(out_dir, "detailed.md")
        markdown.write_detailed(result, path)
        written.append(path)
    if "json" in formats:
        path = os.path.join(out_dir, "findings.json")
        jsonout.write_json(result, path)
        written.append(path)
    if "xlsx" in formats:
        path = os.path.join(out_dir, "registry.xlsx")
        try:
            xlsx.write_xlsx(result, path)
            written.append(path)
        except RuntimeError as exc:
            log.error("XLSX не сформирован: %s", exc)
    return written


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    try:
        formats = resolve_formats(args.formats)
        path = args.config or find_default_config()
        if not path:
            raise ConfigError(
                "конфиг не найден: укажите --config или положите config.yml "
                "рядом (в контейнере — /config/config.yml)"
            )
        config = apply_overrides(load_config(path), args)
    except ConfigError as exc:
        log.error("Ошибка конфигурации: %s", exc)
        return EXIT_CONFIG

    if config.scan.show_values:
        log.warning("Включён --show-values: отчёты будут содержать реальные "
                    "значения и сами станут носителями ПДн")

    log.info("Конфиг: %s | источников: %d | режим: %s", path, len(config.sources),
             "инвентаризация схемы" if config.scan.dry_run else "выборка значений")

    try:
        result = Scanner(config).run()
    except ReadWriteAccessError as exc:
        log.error("Запуск заблокирован: %s", exc)
        return EXIT_ACCESS
    except KeyboardInterrupt:
        log.error("Прервано пользователем")
        return EXIT_ERROR

    console.print_result(result)

    written = write_reports(result, args.out, formats)
    if written:
        log.info("Отчёты записаны:")
        for item in written:
            log.info("  %s", item)

    return EXIT_ERROR if result.errors else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
