"""Genera el informe técnico a partir de las métricas reproducibles."""

import json
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from scripts.charts import build as build_charts
from scripts.train import ARTIFACTS, ROOT

OUTPUT = ROOT / "docs" / "Informe_tecnico_VulnMiner.pdf"
INK = colors.HexColor("#182c36")
MUTED = colors.HexColor("#486070")
GREEN = colors.HexColor("#17604e")
PALE = colors.HexColor("#eaf4ef")
LINE = colors.HexColor("#d6e3e5")
WIDTH = 499

STYLES = {
    "kicker": ParagraphStyle("kicker", fontName="Helvetica-Bold", fontSize=10, leading=14,
                             textColor=GREEN, spaceAfter=13),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=42, leading=48,
                            textColor=INK, spaceAfter=9),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=18, leading=23,
                               textColor=MUTED, spaceAfter=22),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=27, leading=32,
                         textColor=INK, spaceAfter=16),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, leading=17,
                         textColor=GREEN, spaceBefore=13, spaceAfter=6),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10.5, leading=15.3,
                           textColor=INK, spaceAfter=9),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=9, leading=12.7,
                            textColor=MUTED, spaceAfter=6),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8.2, leading=12.5,
                           textColor=INK, backColor=PALE, borderPadding=8, spaceBefore=6, spaceAfter=12),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=9.1, leading=12.2, textColor=INK),
    "head": ParagraphStyle("head", fontName="Helvetica-Bold", fontSize=9.1, leading=11.8,
                           textColor=colors.white),
}


def p(text, style="body"):
    return Paragraph(text, STYLES[style])


def grid(headers, rows, widths):
    contents = [[p(escape(item), "head") for item in headers]]
    contents.extend([[p(escape(str(item)), "cell") for item in row] for row in rows])
    table = Table(contents, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), GREEN),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, LINE),
    ]))
    return table


def page_frame(canvas, doc):
    width, height = A4
    canvas.setTitle("VulnMiner | Informe técnico")
    canvas.setSubject("Laboratorio 1 · Desarrollo de Software Seguro")
    canvas.setAuthor("Proyecto VulnMiner")
    canvas.setFillColor(GREEN)
    canvas.rect(0, height - 8, width, 8, stroke=0, fill=1)
    canvas.setStrokeColor(LINE)
    canvas.line(48, 42, width - 48, 42)
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(48, 28, "VulnMiner  /  Laboratorio 1  /  ESPE")
    canvas.drawRightString(width - 48, 28, f"{doc.page}")


def chart_figure(drawing, width=WIDTH):
    factor = width / drawing.width
    drawing.scale(factor, factor)
    drawing.width *= factor
    drawing.height *= factor
    return drawing


def build():
    metrics = json.loads((ARTIFACTS / "metrics.json").read_text(encoding="utf-8"))
    demo = json.loads((ARTIFACTS / "demo_metrics.json").read_text(encoding="utf-8"))
    charts = build_charts()
    data = metrics["dataset"]
    selected = metrics["selected"]
    comparison = metrics["comparison"]
    results = comparison[selected]["test"]
    names = {"logistic": "Regresión logística", "bernoulli": "Naive Bayes Bernoulli"}
    reserved = demo["proyecto-reservado"]
    contrast = demo["proyecto-contraste"]
    document = SimpleDocTemplate(
        str(OUTPUT), pagesize=A4, leftMargin=48, rightMargin=48,
        topMargin=46, bottomMargin=59, allowSplitting=True,
    )
    story = [
        p("INFORME TÉCNICO · DESARROLLO DE SOFTWARE SEGURO", "kicker"),
        p("VulnMiner", "title"),
        p("Clasificación supervisada de hallazgos en microservicios", "subtitle"),
        p("Universidad de las Fuerzas Armadas ESPE · Laboratorio 1 · 23 de noviembre de 2026", "small"),
        Spacer(1, 11),
        p("Problema y alcance", "h2"),
        p("El laboratorio evalúa si un modelo entrenado con declaraciones de seguridad puede reconocer señales "
          "análogas en repositorios de microservicios. VulnMiner clasifica cinco patrones locales y los vincula "
          "con las taxonomías OWASP Top 10:2025 y OWASP API Security Top 10:2023."),
        p(f"El corpus contiene <b>{data['registros']} registros</b> y el proyecto reservado produjo "
          f"<b>{reserved['hallazgos_potenciales']} hallazgos</b> que cubren las cinco categorías web y cuatro de API "
          "exigidas. Ambos resultados se obtuvieron con casos controlados."),
        p("Arquitectura", "h2"),
        grid(("Componente", "Responsabilidad"), (
            ("Descubrimiento", "Encuentra contextos locales de Compose, manifiestos y carpetas de servicios. "
             "Agrupa los archivos por el directorio del servicio detectado."),
            ("Extracción", "Lee código y configuración de texto y toma la línea como unidad. En YAML incorpora "
             "las claves antecesoras. Conserva la ruta y el número de línea."),
            ("Inferencia", "Aplica el pipeline léxico y el modelo JSON. Cada clasificador devuelve un puntaje "
             "y las señales con contribución positiva."),
            ("Clasificación y salida", "Relaciona los patrones aceptados con CWE y OWASP. La CLI genera un resumen "
             "en consola y reportes JSON y HTML con la evidencia y el estado."),
        ), (119, 380)),
        Spacer(1, 13),
        p("La CLI aplica el modelo guardado. El entrenamiento y los artefactos SEMMA se generan por separado a "
          "partir del CSV. El análisis local lee archivos sin iniciar los servicios."),
        PageBreak(),

        p("Metodología SEMMA", "h1"),
        grid(("Fase", "Procedimiento y evidencia"), (
            ("Sample", "Muestreo por escenarios controlados. Cada caso de riesgo se acompaña de un control con "
             "el mismo contexto. Veinte proyectos sintéticos y sesenta familias se distribuyen en "
             "560 registros de entrenamiento, 120 de validación y 120 de prueba."),
            ("Explore", "Describe etiquetas, formatos, características, longitud y balance. Hay 200 registros "
             "por formato y 400 casos en cada clase binaria. Los notebooks contienen gráficos y su interpretación."),
            ("Modify", "Valida anotación, grupos y duplicados normalizados. Extrae palabras, pares vecinos y "
             "asociaciones de claves y estados. Aprende el vocabulario solo de entrenamiento."),
            ("Model", "Entrena regresión logística regularizada y Naive Bayes Bernoulli. Cada modelo usa "
             "clasificadores uno contra resto y se ajusta mediante validación."),
            ("Assess", "Calcula precisión, recall, F1, matrices y errores por etiqueta. Prueba la CLI sobre "
             "dos repositorios locales anotados fuera del corpus."),
        ), (87, 412)),
        p("Procedencia y etiquetado", "h2"),
        p("Los ejemplos de Python, JavaScript, YAML y Properties son declaraciones sintéticas originales. "
          "El indicador de riesgo se refiere al control representado. La documentación del CSV guarda fuentes, "
          "campos, particiones y criterios de correspondencia CWE–OWASP."),
        p("Transformación y control de filtración", "h2"),
        p(f"El vocabulario final tiene {metrics['feature_count']} rasgos. La regresión usa TF-IDF con "
          "normalización L2 y ponderación de clases por patrón. Naive Bayes usa presencia binaria y suavizado. "
          "Proyecto y familia se mantienen dentro de una sola partición. Los identificadores, las rutas y las "
          "etiquetas se excluyen de la entrada del modelo."),
        p("Entregables de la fase experimental", "h2"),
        p("Dataset y diccionario de datos · Cinco notebooks ejecutados · Matriz de características · "
          "Modelo JSON · Métricas y matrices · Tablas de correspondencia y anotaciones de demostración."),
        PageBreak(),

        p("Resultados de clasificación", "h1"),
        grid(("Clasificador", "Parámetro", "Umbral", "F1 validación", "F1 prueba"), [
            (names[key], f"{item['configuration']['parameter']:.4g}",
             f"{item['configuration']['threshold']:.2f}",
             f"{item['validation']['owasp']['macro_f1']:.3f}", f"{item['test']['owasp']['macro_f1']:.3f}")
            for key, item in comparison.items()
        ], (155, 80, 68, 103, 93)),
        Spacer(1, 12),
        p(f"Se seleccionó <b>{names[selected]}</b>. Se compararon {len(metrics['trials'])} combinaciones. "
          "El desempate favorece menos falsos positivos binarios, un umbral más cercano a 0.55 y, "
          "si persiste el empate, la regresión logística. Los dos modelos empataron en F1 macro OWASP."),
        p("Partición de prueba sintética", "h2"),
        grid(("Etiqueta", "Precisión", "Recall", "F1", "Soporte", "FP", "FN"), [
            (code, f"{record['precision']:.3f}", f"{record['recall']:.3f}", f"{record['f1']:.3f}",
             record["support"], record["fp"], record["fn"])
            for code, record in results["owasp"]["per_label"].items()
        ], (104, 81, 64, 64, 70, 58, 58)),
        Spacer(1, 11),
        p(f"El F1 macro OWASP fue {results['owasp']['macro_f1']:.3f} en {results['n']} registros. "
          f"Matriz binaria con filas de referencia y columnas de predicción: "
          f"{results['binary']['per_label']['vulnerable']['matrix']}. Las matrices por etiqueta y los "
          "resultados de los candidatos están en <font face='Courier'>artifacts/metrics.json</font>.", "small"),
        p("Los puntajes altos corresponden a un corpus pequeño y controlado con estructuras similares. "
          "Las particiones reservadas contienen formulaciones distintas y comparten el vocabulario "
          "de los controles. El resultado depende de esa proximidad."),
        PageBreak(),

        p("Demostración funcional y límites", "h1"),
        grid(("Proyecto", "Servicios", "Archivos", "Hallazgos", "Precisión", "Recall"), (
            ("Reservado", reserved["microservicios"], reserved["archivos_analizados"],
             reserved["hallazgos_potenciales"], f"{reserved['precision']:.3f}", f"{reserved['recall']:.3f}"),
            ("Contraste", contrast["microservicios"], contrast["archivos_analizados"],
             contrast["hallazgos_potenciales"], f"{contrast['precision']:.3f}", f"{contrast['recall']:.3f}"),
        ), (126, 71, 71, 80, 76, 75)),
        Spacer(1, 7),
        chart_figure(charts["generalizacion"]),
        p("Cada coincidencia requiere el mismo archivo, línea y categoría que la anotación manual. "
          "En contraste se omitió A04:2025 en <font face='Courier'>settings.js</font>, línea 3. "
          "El control se expresaba como protocolo HTTP, una forma ausente del entrenamiento. "
          "Los dos proyectos de demostración son maquetas controladas."),
        p("Cobertura y verificación", "h2"),
        p(f"En el proyecto reservado se demostraron {', '.join(reserved['categorias_web_demostradas'])} "
          f"y {', '.join(reserved['categorias_api_demostradas'])}. El catálogo incluye los 20 códigos "
          "y marca las otras 11 categorías como no evaluadas. La confianza carece de calibración "
          "probabilística y la severidad se justifica por el impacto estimado."),
        p("El análisis por línea puede omitir controles indirectos o dependientes de la configuración "
          "efectiva. La extensión prioritaria sería validar con repositorios reales autorizados y "
          "agregar declaraciones de transporte y otros contextos al corpus. La demostración sobre el "
          "proyecto proporcionado por el docente está pendiente."),
        p("Fuentes", "h2"),
        p("ESPE. Laboratorio 1, Desarrollo de Software Seguro. Secciones 4 a 10. "
          "<link href='https://top10.owasp.org/2025/' color='#17604e'>OWASP Top 10:2025</link> · "
          "<link href='https://api-security.owasp.org/editions/2023/en/0x11-t10/' color='#17604e'>"
          "OWASP API Security Top 10:2023</link> · "
          "<link href='https://cwe.mitre.org/' color='#17604e'>MITRE CWE</link>.", "small"),
    ]
    document.build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    print(OUTPUT.relative_to(ROOT))


if __name__ == "__main__":
    build()
