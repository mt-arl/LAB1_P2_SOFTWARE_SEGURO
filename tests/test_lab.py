"""Verifica los mínimos del laboratorio y el flujo real de la CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.corpus import normalize, read
from scripts.train import ARTIFACTS, ROOT
from vulnminer.catalog import API, WEB
from vulnminer.features import evidence
from vulnminer.model import load_model
from vulnminer.reports import render_html
from vulnminer.scanner import scan


class LabAcceptance(unittest.TestCase):
    def test_corpus_minimums_and_partition_independence(self):
        data = normalize(read())
        self.assertGreaterEqual(len(data), 500)
        self.assertGreaterEqual(sum(not item["target"] for item in data), 100)
        for group in ("project", "family"):
            partitions = [{item[group] for item in data if item["partition"] == key}
                          for key in ("train", "validation", "test")]
            self.assertFalse(partitions[0] & partitions[1])
            self.assertFalse(partitions[0] & partitions[2])
            self.assertFalse(partitions[1] & partitions[2])

    def test_cli_reports_catalog_coverage_and_reference_locations(self):
        project = ROOT / "examples" / "proyecto-reservado"
        truth = json.loads((ARTIFACTS / "demo_truth.json").read_text(encoding="utf-8"))[project.name]
        with tempfile.TemporaryDirectory() as directory:
            execution = subprocess.run(
                [sys.executable, "-m", "vulnminer", "scan", str(project), "--output", directory],
                cwd=ROOT, capture_output=True, text=True, check=True,
            )
            output = Path(directory)
            report = json.loads((output / "analisis.json").read_text(encoding="utf-8"))
            html = (output / "analisis.html").read_text(encoding="utf-8")
        self.assertIn("3 microservicios", execution.stdout)
        self.assertEqual(len(report["catalogo"]), 20)
        self.assertEqual(sum(x["estado"] == "no_evaluada" for x in report["catalogo"]), 11)
        self.assertTrue({"Python", "JavaScript"} <= set(report["resumen"]["lenguajes_y_formatos"]))
        findings = report["hallazgos"]
        codes = {code for item in findings for code in item["categorias_owasp"]}
        self.assertGreaterEqual(len(codes & WEB.keys()), 5)
        self.assertGreaterEqual(len(codes & API.keys()), 4)
        self.assertEqual({(x["archivo"], x["linea"], tuple(x["categorias_owasp"])) for x in findings},
                         {(x["archivo"], x["linea"], tuple(x["categorias"])) for x in truth})
        for item in findings:
            self.assertIn(item["id"], html)
            self.assertTrue(item["evidencia"]["fragmento"])
            self.assertEqual(item["estado"], "requiere_verificacion")

    def test_symlink_is_ignored_and_reports_escape_source(self):
        self.assertNotIn("private-example", evidence("api_token = 'private-example'"))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            root.mkdir()
            outside = base / "outside.py"
            outside.write_text("debug_mode = True\n", encoding="utf-8")
            (root / "linked.py").symlink_to(outside)
            (root / "api<&>.py").write_text("debug_mode = True\n", encoding="utf-8")
            result = scan(root, load_model(), ("owasp2025",), root / "reportes")
            formatted = render_html(result)
        self.assertEqual(result["resumen"]["archivos_analizados"], 1)
        self.assertIn("api&lt;&amp;&gt;.py", formatted)
        self.assertNotIn("api<&>.py", formatted)


if __name__ == "__main__":
    unittest.main()
