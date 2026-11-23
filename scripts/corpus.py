"""Construye un corpus de declaraciones de política inertes y controles emparejados."""

import csv
import hashlib
import re
from collections import Counter
from pathlib import Path

from vulnminer.catalog import categories
from vulnminer.features import features, without_comment

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "dataset.csv"
PROJECTS = {
    "train": ("orders", "billing", "products", "members", "calendar", "delivery",
              "payments", "records", "warehouse", "accounts", "training", "offers",
              "support", "inventory"),
    "validation": ("travel", "books", "archives"),
    "test": ("licensing", "surveys", "booking"),
}
# Cada partición tiene cuatro formulaciones propias por control. Ninguna plantilla
# se comparte entre particiones. Cada contraste conserva estructura y contexto.
KEYS = {
    "ownership": {
        "train": ("verify_object_owner", "objectOwnerCheck", "require_ownership", "resource.owner.verify"),
        "validation": ("require_object_ownership", "verifyResourceOwner", "owner_verify_required", "object.owner.check"),
        "test": ("verify_record_owner", "authorizeObjectOwner", "object_ownership_required", "record.owner.validation"),
    },
    "debug": {
        "train": ("debug", "debugMode", "debug_diagnostics", "server.debug.enabled"),
        "validation": ("debug_mode_enabled", "enableDebug", "show_tracebacks", "service.debug.enable"),
        "test": ("debugging_enabled", "debugDiagnostics", "display_debug_traceback", "runtime.debug.mode"),
    },
    "transport": {
        "train": ("require_tls", "tlsRequired", "enforce_https", "transport.encryption.required"),
        "validation": ("require_https_transport", "enforceTLS", "tls_encryption_required", "network.tls.require"),
        "test": ("tls_enforced", "requireEncryptedTransport", "https_required", "connection.transport.tls.required"),
    },
    "rate_limit": {
        "train": ("rate_limit_enabled", "enforceRateLimit", "request_limit", "request.rate.limit"),
        "validation": ("enable_request_throttle", "requestRateLimit", "rate_limit", "requests.quota.limit"),
        "test": ("require_rate_limiting", "enableRequestLimiter", "request_rate_quota", "endpoint.rate.limit"),
    },
    "expiration": {
        "train": ("verify_expiration", "requireTokenExpiration", "session_ttl", "session.expiration.required"),
        "validation": ("verify_token_expiry", "validateSessionExpiration", "token_ttl_seconds", "auth.expiry.required"),
        "test": ("require_session_expiration", "verifyExpiration", "session_expiry_seconds", "token.expiration.check"),
    },
}
KINDS = ("Python", "JavaScript", "YAML", "Properties")
FILES = (
    "api/policies.py", "api/policies.js", "config/application.yml",
    "config/application.properties",
)


def code_for(key, kind, domain, risk, label, index):
    """El código resultante declara valores de prueba y no contiene un servicio ejecutable."""
    if label in {"expiration", "rate_limit"} and kind == "YAML":
        value = "0" if risk else str(45 + 5 * index)
    else:
        enabled = risk if label == "debug" else not risk
        value = str(enabled) if kind == "Python" else str(enabled).lower()
    if kind == "Python":
        return f"{domain}_{key} = {value}"
    if kind == "JavaScript":
        return f"const {domain}{key[0].upper()}{key[1:]} = {value};"
    if kind == "YAML":
        return f"{domain}_{key}: {value}"
    return f"{domain}.{key}={value}"


def generate(path=DATASET):
    rows = []
    for partition, projects in PROJECTS.items():
        for index, domain in enumerate(projects):
            project = f"synthetic/{domain}"
            for label, forms in KEYS.items():
                for form, (kind, file, key) in enumerate(zip(KINDS, FILES, forms[partition])):
                    api = kind in {"Python", "JavaScript", "YAML"} or index % 2 == 0
                    for risk in (False, True):
                        tags = (label,) if risk else ()
                        content = code_for(key, kind, domain, risk, label, index)
                        rows.append({
                            "id": f"{domain}-{label}-{form + 1}-{int(risk)}",
                            "project": project,
                            "source": "Caso controlado original, scripts/corpus.py",
                            "path": file,
                            "family": f"{partition}/{label}/{form + 1}",
                            "language": kind,
                            "partition": partition,
                            "api_context": int(api),
                            "is_vulnerable": int(risk),
                            "patterns": "|".join(tags),
                            "owasp": "|".join(categories(label, api)) if tags else "",
                            "content": content,
                        })
    with path.open("w", encoding="utf-8", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return rows


def read(path=DATASET):
    with path.open(encoding="utf-8", newline="") as infile:
        return list(csv.DictReader(infile))


def normalize(rows):
    """Valida anotación y separación y aplica la misma representación de la CLI."""
    seen = set()
    group_partitions = {}
    fingerprints = {}
    cleaned = []
    for row in rows:
        labels = tuple(filter(None, row["patterns"].split("|")))
        api = str(row["api_context"]) == "1"
        expected = sorted({code for label in labels for code in categories(label, api)})
        annotated = sorted(filter(None, row["owasp"].split("|")))
        if expected != annotated or bool(labels) != (str(row["is_vulnerable"]) == "1"):
            raise ValueError(f"Etiquetas inconsistentes en {row['id']}")
        if row["partition"] not in PROJECTS or not all(row[key] for key in ("id", "project", "family", "content")):
            raise ValueError(f"Registro incompleto o partición inválida: {row['id']}")
        for key in ("project", "family"):
            group = (key, row[key])
            if group_partitions.setdefault(group, row["partition"]) != row["partition"]:
                raise ValueError(f"Filtración entre particiones: {group}")
        content = without_comment(row["content"]).strip()
        fingerprint = hashlib.sha256(re.sub(r"\s+", "", content).lower().encode()).hexdigest()
        if fingerprints.setdefault(fingerprint, (row["partition"], labels)) != (row["partition"], labels):
            raise ValueError(f"Texto duplicado entre particiones o con etiquetas contradictorias: {row['id']}")
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        cleaned.append({
            **row, "content": content, "target": labels, "is_api": api,
            "features": features(content),
        })
    return cleaned


def describe(rows):
    return {
        "registros": len(rows),
        "proyectos": len({row["project"] for row in rows}),
        "familias": len({row["family"] for row in rows}),
        "duplicados_exactos": len(rows) - len({row["content"] for row in rows}),
        "faltantes_requeridos": sum(
            not row[key] for row in rows for key in ("id", "project", "source", "path", "content")
        ),
        "particiones": dict(Counter(row["partition"] for row in rows)),
        "lenguajes_formatos": dict(Counter(row["language"] for row in rows)),
        "clases": dict(Counter("vulnerable" if str(row["is_vulnerable"]) == "1" else "no vulnerable" for row in rows)),
        "categorias": dict(sorted(Counter(
            code for row in rows for code in row["owasp"].split("|") if code
        ).items())),
        "longitud_caracteres": {
            "min": min(len(row["content"]) for row in rows),
            "promedio": round(sum(len(row["content"]) for row in rows) / len(rows), 2),
            "max": max(len(row["content"]) for row in rows),
        },
    }


if __name__ == "__main__":
    print(describe(generate()))
