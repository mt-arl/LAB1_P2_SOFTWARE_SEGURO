"""Dibuja figuras vectoriales para los notebooks a partir de los resultados guardados."""

import json
from collections import Counter

from reportlab.graphics import renderSVG
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors

from scripts import corpus
from scripts.train import ARTIFACTS

INK = colors.HexColor("#152c36")
MUTED = colors.HexColor("#415967")
GRID = colors.HexColor("#dbe5e8")
TEAL = colors.HexColor("#176b56")
BLUE = colors.HexColor("#376a99")
CHARTS = ARTIFACTS / "charts"


def horizontal(title, unit, names, groups, ceiling, step):
    height = 125 + 24 * len(names) + 5 * len(groups)
    drawing = Drawing(640, height)
    drawing.add(Rect(0, 0, 640, height, strokeColor=None, fillColor=colors.white))
    drawing.add(String(16, height - 24, title, fontName="Helvetica-Bold", fontSize=16, fillColor=INK))
    drawing.add(String(16, height - 44, unit, fontSize=10, fillColor=MUTED))
    chart = HorizontalBarChart()
    chart.x, chart.y = 162, 42
    chart.width, chart.height = 451, height - 105
    chart.data = [list(values)[::-1] for _, values in groups]
    chart.categoryAxis.categoryNames = list(names)[::-1]
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 9
    chart.categoryAxis.labels.fillColor = INK
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.labels.dx = -5
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = ceiling
    chart.valueAxis.valueStep = step
    chart.valueAxis.labels.fontSize = 9
    chart.valueAxis.strokeColor = GRID
    chart.valueAxis.gridStrokeColor = GRID
    chart.valueAxis.visibleGrid = True
    for index, (name, _) in enumerate(groups):
        fill = (TEAL, BLUE)[index]
        chart.bars[index].fillColor = fill
        chart.bars[index].strokeColor = None
        if name:
            x = 165 + 178 * index
            drawing.add(Rect(x, 8, 10, 10, strokeColor=None, fillColor=fill))
            drawing.add(String(x + 15, 9, name, fontSize=9, fillColor=MUTED))
    drawing.add(chart)
    return drawing


def build():
    rows = corpus.read()
    clean = corpus.normalize(rows)
    data = corpus.describe(rows)
    metrics = json.loads((ARTIFACTS / "metrics.json").read_text(encoding="utf-8"))
    demos = json.loads((ARTIFACTS / "demo_metrics.json").read_text(encoding="utf-8"))
    terms = Counter(term[2:] for row in clean for term in sorted(row["features"]) if term.startswith("a:"))
    top = sorted(terms, key=lambda key: (-terms[key], key))[:8]
    split = ("train", "validation", "test")
    ratios = [sum(row["target"] != () and row["partition"] == name for row in clean)
              / data["particiones"][name] for name in split]
    models = ("logistic", "bernoulli")
    fixtures = ("proyecto-reservado", "proyecto-contraste")
    charts = {
        "categorias": horizontal("Etiquetas OWASP en el corpus", "Conteo multietiqueta",
            list(data["categorias"]), [("", data["categorias"].values())], 100, 20),
        "clases": horizontal("Distribución de casos", "Registros por etiqueta binaria",
            list(data["clases"]), [("", data["clases"].values())], 500, 100),
        "lenguajes": horizontal("Lenguajes y formatos", "Registros por formato de entrada",
            list(data["lenguajes_formatos"]), [("", data["lenguajes_formatos"].values())], 250, 50),
        "rasgos": horizontal("Rasgos observados con mayor frecuencia", "Registros con asociación léxica clave–estado",
            top, [("", [terms[key] for key in top])], 180, 30),
        "desbalance": horizontal("Proporción de casos por partición", "Fracción de registros de cada partición",
            ("Entrenamiento", "Validación", "Prueba"),
            [("Vulnerables", ratios), ("No vulnerables", [1 - ratio for ratio in ratios])], 1, 0.2),
        "comparacion": horizontal("Comparación supervisada", "F1 macro por categoría OWASP",
            ("Regresión logística", "Naive Bayes Bernoulli"),
            [(name, [metrics["comparison"][model][key]["owasp"]["macro_f1"] for model in models])
             for name, key in (("Validación", "validation"), ("Prueba", "test"))], 1, 0.2),
        "generalizacion": horizontal("Evaluación funcional de la CLI", "Coincidencias por archivo, línea y categoría",
            fixtures, [("Precisión", [demos[name]["precision"] for name in fixtures]),
                       ("Recall", [demos[name]["recall"] for name in fixtures])], 1, 0.2),
    }
    CHARTS.mkdir(parents=True, exist_ok=True)
    for name, chart in charts.items():
        svg = renderSVG.drawToString(chart)
        clean_svg = "\n".join(line.rstrip() for line in svg.splitlines()) + "\n"
        (CHARTS / f"{name}.svg").write_text(clean_svg, encoding="utf-8")
    return charts


if __name__ == "__main__":
    for generated in build():
        print(f"artifacts/charts/{generated}.svg")
