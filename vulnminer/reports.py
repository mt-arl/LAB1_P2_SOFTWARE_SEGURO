"""Reportes independientes con contenido del repositorio escapado."""

import json
import os
from collections import Counter
from html import escape
from tempfile import NamedTemporaryFile

STYLE = """
:root{color-scheme:light;--ink:#182a32;--muted:#485e66;--line:#d5e0dc;--accent:#186350}
*{box-sizing:border-box}body{margin:0;background:#edf3ef;color:var(--ink);font:16px/1.55 system-ui,sans-serif}
main{width:min(1140px,calc(100% - 36px));margin:auto;padding:28px 0 50px}
header{background:#14372f;color:#fff;padding:35px;border-radius:14px}h1,h2,h3{line-height:1.2}
h1{font-size:clamp(2rem,5vw,3.25rem);margin:.25rem 0}h2{margin-top:34px}
header p{color:#d8ece2;margin:0}.subtitle{margin-bottom:9px}
a{color:#16614d}nav{margin-top:18px;display:flex;gap:18px;flex-wrap:wrap}
nav a{color:#fff}dl.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(153px,1fr));gap:12px}
.summary div,article,.table-wrap{background:#fff;border:1px solid var(--line);border-radius:10px;padding:15px}
dt{color:var(--muted)}dd{margin:0;font-weight:700}.summary dd{font-size:1.55rem}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}
th,td{border-bottom:1px solid var(--line);padding:8px 12px;vertical-align:top}
article{margin-bottom:12px;padding:20px}article h3{margin-top:0}article p{margin:.45rem 0}
.detail{color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef4f1;padding:10px;border-radius:6px}
code{overflow-wrap:anywhere}small{color:var(--muted)}:target{scroll-margin-top:12px}
"""


def esc(value):
    return escape(str(value), quote=True)


def table(headers, rows):
    head = "".join(f"<th scope='col'>{esc(value)}</th>" for value in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(value)}</td>" for value in row) + "</tr>" for row in rows)
    return f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def render_html(report):
    totals = report["resumen"]
    findings = report["hallazgos"]
    by_service = Counter(item["microservicio"] for item in findings)
    by_code = Counter(code for item in findings for code in item["categorias_owasp"])
    summary = "".join(f"<div><dt>{title}</dt><dd>{totals[key]}</dd></div>" for title, key in (
        ("Microservicios", "microservicios"), ("Archivos analizados", "archivos_analizados"),
        ("Hallazgos potenciales", "hallazgos_potenciales"), ("Pendientes de revisión", "pendientes_de_revision"),
    ))
    cards = []
    for item in findings:
        tags = ", ".join(item["categorias_owasp"]) or "Pendiente"
        fragment = item["evidencia"]["fragmento"]
        signals = ", ".join(item["evidencia"]["senales_modelo"])
        severity = item["severidad"]
        cards.append(f"""
<article id="{esc(item['id'])}">
<h3>{esc(item['descripcion'])}</h3>
<p class="detail"><code>{esc(item['id'])}</code> · {esc(item['microservicio'])} ·
<code>{esc(item['archivo'])}:{item['linea']}</code> · {esc(item['lenguaje'])}</p>
<p><strong>OWASP</strong> {esc(tags)} · <strong>CWE</strong> {esc(item['cwe'] or 'Pendiente')}</p>
<p><strong>Confianza</strong> {item['confianza']:.2%} ·
<strong>Estado</strong> {esc(item['estado'].replace('_', ' '))}</p>
<pre>{esc(fragment)}</pre>
<p><strong>Señales del modelo</strong> {esc(signals)}</p>
<p><strong>Severidad {esc(severity['nivel'])}.</strong> {esc(severity['justificacion'])}</p>
<p><strong>Remediación</strong> {esc(item['remediacion'])}</p>
</article>""")
    service_rows = [(x["nombre"], x["directorio"], x["descubrimiento"], by_service[x["nombre"]])
                    for x in report["microservicios"]]
    if by_service["raíz"]:
        service_rows.append(("raíz", ".", "archivos sin servicio asignado", by_service["raíz"]))
    category_rows = [(x["codigo"], x["nombre"], x["estado"].replace("_", " "), by_code[x["codigo"]])
                     for x in report["catalogo"]]
    omitted = (
        "<h2>Archivos omitidos</h2>" + table(("Archivo", "Motivo"),
            [(x["archivo"], x["motivo"]) for x in report["archivos_omitidos"]])
        if report["archivos_omitidos"] else ""
    )
    project = esc(report["proyecto"])
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnMiner · {project}</title><style>{STYLE}</style></head><body><main>
<header><p>VulnMiner · Análisis estático</p><h1>{project}</h1>
<p class="subtitle">Modelo {esc(report['modelo']['algoritmo'])} · {esc(', '.join(report['estandares']))}</p>
<nav aria-label="Secciones"><a href="#servicios">Microservicios</a><a href="#hallazgos">Hallazgos</a>
<a href="#categorias">Cobertura OWASP</a></nav></header>
<dl class="summary">{summary}</dl>
<h2 id="servicios">Microservicios</h2>
{table(("Servicio", "Directorio", "Descubrimiento", "Hallazgos"), service_rows)}
<h2 id="hallazgos">Hallazgos</h2>
<p>Los resultados describen señales estáticas. El estado indica si requieren verificación o revisión adicional.</p>
{''.join(cards) or '<p>Sin hallazgos potenciales dentro de la cobertura del modelo.</p>'}
<h2 id="categorias">Cobertura OWASP</h2>
{table(("Código", "Categoría", "Evaluación", "Hallazgos"), category_rows)}
{omitted}
</main></body></html>
"""


def write_reports(report, output, formats):
    output.mkdir(parents=True, exist_ok=True)
    for format_name in formats:
        path = output / f"analisis.{format_name}"
        content = (json.dumps(report, ensure_ascii=False, indent=2) + "\n"
                   if format_name == "json" else render_html(report))
        temporary = None
        try:
            with NamedTemporaryFile(mode="w", dir=output, encoding="utf-8", delete=False) as target:
                temporary = target.name
                target.write(content)
            os.replace(temporary, path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        yield path
