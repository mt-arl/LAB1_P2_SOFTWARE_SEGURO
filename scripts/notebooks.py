"""Reconstruye y ejecuta los cinco notebooks con un intérprete Python local."""

import contextlib
import io
import json
from pathlib import Path

from scripts.train import ROOT

SETUP = """import json
import sys
from pathlib import Path

cwd = Path.cwd().resolve()
ROOT = next(folder for folder in (cwd, *cwd.parents)
            if (folder / "data" / "dataset.csv").is_file()
            and (folder / "scripts" / "corpus.py").is_file())
sys.path.insert(0, str(ROOT))

if "show_chart" not in globals():
    def show_chart(name):
        from IPython.display import SVG, display
        display(SVG(filename=str(ROOT / "artifacts" / "charts" / f"{name}.svg")))
"""

NOTEBOOKS = {
    "01_sample": [
        ("md", "# Sample\nConstrucción de un corpus etiquetado con procedencia y particiones por proyecto y familia."),
        ("code", """from scripts import corpus
rows = corpus.generate()
for key, value in corpus.describe(rows).items():
    print(f"{key} = {value}")"""),
        ("md", "Se construyeron controles emparejados para cinco patrones. Cambia el estado de la declaración y se conserva su contexto. Cada grupo sintético y familia pertenece a una sola partición. Las variantes de un mismo patrón comparten vocabulario técnico."),
        ("code", """import csv
with (ROOT / "data" / "cwe_owasp.csv").open(encoding="utf-8") as stream:
    for row in csv.DictReader(stream):
        print(row["patron"], row["cwe"], row["owasp_2025"], row["owasp_api_2023"] or "Sin etiqueta API")"""),
        ("md", "El diccionario en `data/README.md` documenta las columnas y el origen sintético. La etiqueta positiva describe una política adversa en el escenario controlado."),
    ],
    "02_explore": [
        ("md", "# Explore\nDistribuciones, calidad y representatividad del corpus."),
        ("code", """from scripts import corpus
rows = corpus.read()
summary = corpus.describe(rows)
print(json.dumps(summary, ensure_ascii=False, indent=2))
clean = corpus.normalize(rows)
print("Filas con etiquetas inconsistentes o rechazadas:", len(rows) - len(clean))"""),
        ("code", """for name in ("categorias", "clases", "lenguajes", "rasgos", "desbalance"):
    show_chart(name)"""),
        ("md", "La clase binaria está balanceada en las tres particiones. Las categorías de API tienen menor soporte porque requieren contexto. Las frecuencias se refieren a registros, que pueden contribuir a dos categorías OWASP. Los ejemplos se concentran en configuraciones o declaraciones cortas y en cuatro formatos. La repetición semántica entre plantillas limita la diversidad del corpus."),
    ],
    "03_modify": [
        ("md", "# Modify\nNormalización, comprobación de particiones y representación numérica compartida."),
        ("code", """from scripts import corpus
from scripts.train import vocabulary_for
from vulnminer.model import vectorize
rows = corpus.normalize(corpus.read())
train = [row for row in rows if row["partition"] == "train"]
vocabulary = vocabulary_for(train)
vectors = [vectorize(row["features"], vocabulary) for row in rows]
print("Dimensiones TF-IDF", len(vectors), len(vocabulary))
print("Media de rasgos distintos por fila", round(sum(map(len, vectors)) / len(vectors), 2))
print("Ejemplo de rasgos y pesos")
for item, weight in list(vectors[0].items())[:8]:
    print(item, round(weight, 4))"""),
        ("code", """projections = {}
for row, vector in zip(rows, vectors):
    projections.setdefault(row["partition"], set()).add(tuple(vector))
for name, values in projections.items():
    print(name, "vectores distintos", len(values))
for name in ("validation", "test"):
    print(name, "vectores iguales a train", len(projections[name] & projections["train"]))"""),
        ("md", "La extracción conserva tokens, pares vecinos y asociaciones clave–estado normalizadas. El vocabulario y la ponderación se ajustan solo sobre entrenamiento. La regresión usa TF-IDF con norma L2 y pondera el desbalance uno contra resto. Naive Bayes usa presencia binaria y suavizado. El entrenamiento exporta la matriz del modelo seleccionado a `artifacts/features.csv`."),
    ],
    "04_model": [
        ("md", "# Model\nEntrenamiento y selección por F1 macro OWASP en validación."),
        ("code", """from scripts.train import run
results = run()
print("Criterio:", results["selection_rule"])
print("Combinaciones evaluadas:", len(results["trials"]))
for algorithm, item in results["comparison"].items():
    print(algorithm, item["configuration"])"""),
        ("md", "Los clasificadores se ajustan de forma independiente para cada patrón. La comparación usa regularización L2 o suavizado como hiperparámetro, más un umbral de decisión ajustado en validación. El modelo se serializa a JSON con pesos, interceptos, umbrales, vocabulario y huella del CSV. `features.py` reproduce la misma extracción durante la inferencia."),
    ],
    "05_assess": [
        ("md", "# Assess\nEvaluación sobre la partición reservada y dos repositorios fuera del corpus."),
        ("code", """from scripts.train import ARTIFACTS
from scripts.demo import evaluate_demo
results = json.loads((ARTIFACTS / "metrics.json").read_text(encoding="utf-8"))
item = results["comparison"][results["selected"]]["test"]
print("Registros de prueba:", item["n"])
print("F1 macro OWASP:", round(item["owasp"]["macro_f1"], 4))
print("Categoría   Precisión   Recall       F1   Soporte    TP    FP    FN    TN")
for key, row in item["owasp"]["per_label"].items():
    print(f"{key:10} {row['precision']:9.3f} {row['recall']:8.3f} {row['f1']:8.3f} "
          f"{row['support']:9} {row['tp']:5} {row['fp']:5} {row['fn']:5} {row['tn']:5}")
print("Matriz binaria [[TN, FP], [FN, TP]]:", item["binary"]["per_label"]["vulnerable"]["matrix"])
print("Errores:", len(item["errors"]))
print("Sin evaluación:", ", ".join(item["unassessed_owasp"]))"""),
        ("code", """demo = evaluate_demo()
for name, row in demo.items():
    print(name, "precisión", round(row["precision"], 3), "recall", round(row["recall"], 3))
    print("Falsos positivos:", row["falsos_positivos"])
    print("Falsos negativos:", row["falsos_negativos"])"""),
        ("code", """show_chart("comparacion")
show_chart("generalizacion")"""),
        ("md", "La prueba sintética premia el aprendizaje de estados y términos compartidos. En el contraste, el transporte expresado como protocolo produjo un falso negativo en A04. La métrica funcional exige coincidencia de archivo, línea y etiqueta, y la anotación de referencia es manual. Los repositorios son controlados y la demostración con el proyecto del docente queda pendiente."),
    ],
}


def execute(cells):
    result = []
    count = 0
    namespace = {"__name__": "__main__"}
    outputs = []

    def show_chart(name):
        svg = (ROOT / "artifacts" / "charts" / f"{name}.svg").read_text(encoding="utf-8")
        outputs.append({"output_type": "display_data", "metadata": {},
                        "data": {"image/svg+xml": svg, "text/plain": f"Figura {name}"}})

    namespace["show_chart"] = show_chart
    for index, (kind, source) in enumerate(cells):
        cell = {"id": f"cell-{index + 1}", "metadata": {}, "source": source.splitlines(keepends=True)}
        if kind == "md":
            result.append({**cell, "cell_type": "markdown"})
            continue
        count += 1
        outputs = []
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exec(compile(source, f"celda_{index + 1}", "exec"), namespace)
        if stdout.getvalue():
            outputs.insert(0, {"output_type": "stream", "name": "stdout",
                               "text": stdout.getvalue().splitlines(keepends=True)})
        result.append({**cell, "cell_type": "code", "execution_count": count, "outputs": outputs})
    return result


def build():
    if Path.cwd().resolve() != ROOT:
        raise RuntimeError("Ejecuta el generador de notebooks desde la raíz de VulnMiner")
    for name, cells in NOTEBOOKS.items():
        notebook = {
            "cells": execute([cells[0], ("code", SETUP), *cells[1:]]),
            "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                         "language_info": {"name": "python", "file_extension": ".py", "mimetype": "text/x-python"}},
            "nbformat": 4, "nbformat_minor": 5,
        }
        path = ROOT / "notebooks" / f"{name}.ipynb"
        path.write_text(json.dumps(notebook, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    build()
