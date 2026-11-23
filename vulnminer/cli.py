"""Punto de entrada de VulnMiner."""

import argparse
import sys
from pathlib import Path

from .catalog import STANDARDS
from .model import DEFAULT_MODEL, load_model
from .reports import write_reports
from .scanner import scan


def choices(values, raw):
    requested = tuple(dict.fromkeys(item.strip() for item in raw.split(",")))
    invalid = set(requested) - set(values)
    if invalid:
        raise argparse.ArgumentTypeError(f"Opciones disponibles: {', '.join(values)}")
    return requested


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vulnminer", description="Análisis estático local de microservicios")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("scan", help="Analizar el repositorio y generar reportes")
    command.add_argument("path", type=Path, help="Directorio raíz del repositorio")
    command.add_argument("--standards", type=lambda raw: choices(STANDARDS, raw), default=tuple(STANDARDS))
    command.add_argument("--format", type=lambda raw: choices(("json", "html"), raw), default=("json", "html"))
    command.add_argument("--output", type=Path, default=Path("reportes"), help="Directorio de salida")
    command.add_argument("--model", type=Path, default=DEFAULT_MODEL, help="Artefacto JSON de modelo")
    args = parser.parse_args(argv)
    root, output = args.path.resolve(), args.output.resolve()
    if not root.is_dir():
        parser.error(f"El directorio de análisis no existe: {root}")
    if output == root:
        parser.error("Usa un directorio de reportes distinto de la raíz analizada")
    try:
        model = load_model(args.model)
        report = scan(root, model, args.standards, output)
        totals = report["resumen"]
        print(f"VulnMiner · {report['proyecto']}")
        print(f"{totals['microservicios']} microservicios, {totals['archivos_analizados']} archivos analizados, "
              f"{totals['hallazgos_potenciales']} hallazgos potenciales "
              f"({totals['pendientes_de_revision']} pendientes de clasificación)")
        for item in report["hallazgos"]:
            codes = ", ".join(item["categorias_owasp"]) or "pendiente"
            print(f"  {item['microservicio']} · {item['archivo']}:{item['linea']} · {codes} · {item['confianza']:.2f}")
        for path in write_reports(report, output, args.format):
            print(path)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0
