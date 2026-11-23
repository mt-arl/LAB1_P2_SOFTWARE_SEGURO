"""Descubre servicios y aplica inferencia local sin importar ni ejecutar el proyecto."""

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .catalog import CONTROLS, STANDARDS, categories
from .features import api_context, eligible, evidence, without_comment
from .model import predict

COMPOSE = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "Pipfile", "Dockerfile"}
LANGUAGES = {".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
             ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript"}
CONFIG = {".yml", ".yaml", ".json", ".toml", ".properties", ".ini", ".xml"}
EXCLUDED = {"node_modules", "vendor", "dist", "build", "__pycache__", "coverage", "reportes",
            "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Service:
    directory: Path
    name: str
    discovery: str


def file_language(path):
    if path.suffix.lower() in LANGUAGES:
        return LANGUAGES[path.suffix.lower()]
    if path.suffix.lower() in CONFIG or path.name in MANIFESTS or path.name.startswith("Dockerfile."):
        return {
            ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".toml": "TOML",
            ".properties": "Properties", ".ini": "INI", ".xml": "XML",
        }.get(path.suffix.lower(), "Configuración")
    return None


def walk(root, output):
    for folder, directories, files in os.walk(root, followlinks=False):
        current = Path(folder)
        directories[:] = sorted(
            name for name in directories if not name.startswith(".") and name not in EXCLUDED
            and not (current / name).is_symlink()
            and (current / name) != output
        )
        for name in sorted(files):
            path = current / name
            if (not name.startswith(".") and name not in EXCLUDED and not path.is_symlink()
                    and path.is_file() and file_language(path)):
                yield path


def source_text(path):
    try:
        with path.open("rb") as source:
            content = source.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            return None, "excede el límite de 1 MiB"
        if b"\x00" in content:
            return None, "archivo con contenido binario"
        return content.decode("utf-8-sig"), ""
    except (OSError, UnicodeError) as exc:
        return None, type(exc).__name__


def compose_services(text, base, root):
    """Reconoce el subconjunto de Compose con contextos locales literales."""
    services = []
    declared = False
    section_indent = None
    child_indent = None
    service_name = None
    build_indent = None
    for original in text.splitlines():
        line = without_comment(original).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        clean = line.strip()
        if indent == 0:
            if declared and clean != "services:":
                break
            declared = clean == "services:"
            section_indent = indent
            continue
        if not declared or indent <= section_indent:
            continue
        if child_indent is None:
            child_indent = indent
        if indent == child_indent:
            key = re.fullmatch(r"([\w.-]+):", clean)
            service_name = key.group(1) if key else None
            build_indent = None
            continue
        if not service_name:
            continue
        if build_indent is not None and indent <= build_indent:
            build_indent = None
        key, sep, value = clean.partition(":")
        if key == "build" and not value.strip():
            build_indent = indent
        if key != "build" and not (key == "context" and build_indent is not None):
            continue
        if not sep or not value.strip():
            continue
        value = value.strip().strip("'\042")
        if not value or any(char in value for char in "$\x60{}[]") or "://" in value:
            continue
        location = (base / value).resolve()
        if location.is_dir() and location.is_relative_to(root) and location != root:
            services.append(Service(location, service_name, "Compose"))
    return services


def discover(root, files, sources):
    selected = {}
    for path in files:
        if path.name in COMPOSE and path in sources:
            for service in compose_services(sources[path], path.parent, root):
                selected.setdefault(service.directory, service)
    compose_dirs = set(selected)

    manifest_dirs = sorted(
        {path.parent for path in files if path.name in MANIFESTS and path.parent != root},
        key=lambda path: (len(path.parts), path.as_posix()),
    )
    for directory in manifest_dirs:
        if (any(directory.is_relative_to(service) for service in selected)
                or any(service.is_relative_to(directory) for service in compose_dirs)):
            continue
        selected[directory] = Service(directory, directory.name, "manifiesto")
    for path in files:
        parts = path.relative_to(root).parts
        if len(parts) >= 3 and parts[0] in {"services", "microservices", "apps"}:
            directory = root.joinpath(*parts[:2])
            if not any(directory.is_relative_to(service) or service.is_relative_to(directory)
                       for service in selected):
                selected[directory] = Service(directory, directory.name, "estructura")
    names = [service.name for service in selected.values()]
    return sorted(
        (Service(item.directory, item.name if names.count(item.name) == 1 else item.directory.relative_to(root).as_posix(), item.discovery)
         for item in selected.values()),
        key=lambda item: item.directory.relative_to(root).as_posix(),
    )


def units(path, source):
    parents = []
    nested = path.suffix.lower() in {".yaml", ".yml"}
    for number, original in enumerate(source.splitlines(), 1):
        line = without_comment(original).rstrip()
        if not line.strip() or len(line) > 1500:
            continue
        if nested:
            depth = len(line) - len(line.lstrip())
            while parents and parents[-1][0] >= depth:
                parents.pop()
            if re.fullmatch(r"[\w.-]+:", line.strip()):
                parents.append((depth, line.strip()[:-1]))
                continue
        context = " ".join([*(value for _, value in parents), line.strip()])
        if eligible(context):
            yield number, context, line


def scan(root, model, standards, output):
    paths = list(walk(root, output))
    sources = {}
    skipped = []
    for path in paths:
        source, reason = source_text(path)
        if reason:
            skipped.append({"archivo": path.relative_to(root).as_posix(), "motivo": reason})
        else:
            sources[path] = source

    services = discover(root, paths, sources)
    service_paths = sorted(services, key=lambda service: -len(service.directory.parts))
    selected_catalog = {code: title for standard in standards for code, title in STANDARDS[standard].items()}
    coverage = {code for control in CONTROLS.values() for code in (control.web, control.api) if code}
    findings = []
    languages = set()
    for path, source in sources.items():
        relative = path.relative_to(root).as_posix()
        service = next((item.name for item in service_paths if path.is_relative_to(item.directory)), "raíz")
        language = file_language(path)
        languages.add(language)
        is_api = api_context(relative, source)
        for line, context, original in units(path, source):
            for label, confidence, categorized, signals in predict(model, context, include_pending=True):
                control = CONTROLS[label]
                codes = [code for code in categories(label, is_api) if code in selected_catalog]
                if not codes:
                    continue
                severity = {
                    "nivel": control.severity if categorized else "pendiente",
                    "justificacion": control.impact if categorized else "La evidencia requiere revisión antes de estimar impacto.",
                }
                key = f"{relative}:{line}:{label}"
                findings.append({
                    "id": "VM-" + hashlib.sha256(key.encode()).hexdigest()[:12],
                    "microservicio": service, "archivo": relative, "linea": line, "lenguaje": language,
                    "descripcion": control.description if categorized else "Patrón de seguridad pendiente de clasificación.",
                    "evidencia": {"fragmento": evidence(original), "senales_modelo": signals},
                    "categorias_owasp": codes if categorized else [],
                    "cwe": control.cwe if categorized else None,
                    "confianza": round(confidence, 4), "severidad": severity,
                    "remediacion": control.remediation if categorized else "Revisar el contexto y corroborar el control efectivo.",
                    "estado": "requiere_verificacion" if categorized else "pendiente_de_revision",
                })
    return {
        "version_reporte": 1, "proyecto": root.name, "estandares": list(standards),
        "modelo": {"algoritmo": model["algorithm"], "version": model["version"],
                   "huella_dataset": model["dataset_sha256"]},
        "resumen": {
            "microservicios": len(services), "archivos_analizados": len(sources),
            "archivos_omitidos": len(skipped), "lenguajes_y_formatos": sorted(languages),
            "hallazgos_potenciales": len(findings),
            "pendientes_de_revision": sum(item["estado"] == "pendiente_de_revision" for item in findings),
        },
        "microservicios": [
            {"nombre": service.name, "directorio": service.directory.relative_to(root).as_posix(),
             "descubrimiento": service.discovery}
            for service in services
        ],
        "catalogo": [
            {"codigo": code, "nombre": title,
             "estado": "evaluada_en_laboratorio" if code in coverage else "no_evaluada"}
            for code, title in selected_catalog.items()
        ],
        "archivos_omitidos": skipped, "hallazgos": findings,
    }
