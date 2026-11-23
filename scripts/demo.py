"""Ejecuta la CLI y compara archivo, línea y categoría con anotaciones de referencia."""

import json
import subprocess
import sys

from scripts.train import ARTIFACTS, ROOT, save_json
from vulnminer.catalog import API, WEB


def evaluate_demo():
    expected = json.loads((ARTIFACTS / "demo_truth.json").read_text(encoding="utf-8"))
    results = {}
    for project, directory in (("proyecto-reservado", "reservado"), ("proyecto-contraste", "contraste")):
        target = ARTIFACTS / "demo" / directory
        execution = subprocess.run(
            [sys.executable, "-m", "vulnminer", "scan", str(ROOT / "examples" / project),
             "--standards", "owasp2025,api2023", "--format", "json,html", "--output", str(target)],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        print(execution.stdout.replace(f"{ROOT}/", ""), end="")
        report = json.loads((target / "analisis.json").read_text(encoding="utf-8"))
        gold = {(x["archivo"], x["linea"], code) for x in expected[project] for code in x["categorias"]}
        predictions = {(x["archivo"], x["linea"], code)
                       for x in report["hallazgos"] for code in x["categorias_owasp"]}
        true = gold & predictions
        codes = {item[2] for item in true}
        tp, fp, fn = len(true), len(predictions - gold), len(gold - predictions)
        results[project] = {
            **report["resumen"], "coincidencias": tp, "precision": tp / (tp + fp) if tp + fp else 0,
            "recall": tp / (tp + fn) if tp + fn else 0,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0,
            "falsos_positivos": sorted(predictions - gold), "falsos_negativos": sorted(gold - predictions),
            "categorias_web_demostradas": sorted(codes & WEB.keys()),
            "categorias_api_demostradas": sorted(codes & API.keys()),
        }
    save_json(ARTIFACTS / "demo_metrics.json", results)
    return results


if __name__ == "__main__":
    evaluate_demo()
