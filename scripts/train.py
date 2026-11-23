"""Ajusta modelos en train, selecciona en validation y evalúa en test."""

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from scripts import corpus
from vulnminer.catalog import API, LABELS, WEB, categories
from vulnminer.features import FEATURE_VERSION
from vulnminer.model import DEFAULT_MODEL, MODEL_VERSION, encode, predict, sigmoid, vectorize

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"


def save_json(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def vocabulary_for(rows):
    counts = Counter(term for row in rows for term in row["features"])
    return {
        term: 1 + math.log((1 + len(rows)) / (1 + count))
        for term, count in sorted(counts.items()) if count >= 2
    }


def logistic_fit(rows, vectors, label, strength):
    weights = dict.fromkeys(sorted({term for row in vectors for term in row}), 0.0)
    positives = sum(label in row["target"] for row in rows)
    n = len(rows)
    intercept = 0.0
    for epoch in range(160):
        gradient = dict.fromkeys(weights, 0.0)
        offset = 0.0
        for example, vector in zip(rows, vectors):
            target = int(label in example["target"])
            scale = n / (2 * (positives if target else n - positives))
            logit = intercept + sum(weights[term] * value for term, value in vector.items())
            error = (sigmoid(logit) - target) * scale
            offset += error
            for term, value in vector.items():
                gradient[term] += error * value
        step = 2.5 / math.sqrt(1 + epoch / 12)
        intercept -= step * offset / n
        for term in weights:
            weights[term] -= step * (gradient[term] / n + strength * weights[term])
    return intercept, weights


def bernoulli_fit(rows, vocabulary, label, alpha):
    positive = Counter()
    negative = Counter()
    count = sum(label in row["target"] for row in rows)
    for row in rows:
        (positive if label in row["target"] else negative).update(row["features"])
    # Prior empírico y ausencia de rasgos incorporados al intercepto.
    intercept = math.log(count / (len(rows) - count))
    weights = {}
    for term in vocabulary:
        probability = (positive[term] + alpha) / (count + 2 * alpha)
        alternative = (negative[term] + alpha) / (len(rows) - count + 2 * alpha)
        intercept += math.log((1 - probability) / (1 - alternative))
        weights[term] = math.log(probability / alternative) - math.log((1 - probability) / (1 - alternative))
    return intercept, weights


def fit(rows, algorithm, parameter):
    vocabulary = vocabulary_for(rows)
    vectors = [vectorize(row["features"], vocabulary) for row in rows] if algorithm == "logistic" else []
    classifiers = {}
    for label in LABELS:
        if algorithm == "logistic":
            intercept, weights = logistic_fit(rows, vectors, label, parameter)
        else:
            intercept, weights = bernoulli_fit(rows, vocabulary, label, parameter)
        classifiers[label] = {
            "intercept": intercept,
            "weights": {term: value for term, value in weights.items() if abs(value) > 1e-9},
            "threshold": 0.5,
        }
    return {
        "version": MODEL_VERSION, "feature_version": FEATURE_VERSION,
        "algorithm": algorithm, "parameter": parameter, "vocabulary": vocabulary,
        "classifiers": classifiers, "review_floor": 0.40,
        "dataset_sha256": hashlib.sha256(corpus.DATASET.read_bytes()).hexdigest(),
    }


def measure(actual, predicted, labels):
    per_label = {}
    for label in labels:
        counts = [0, 0, 0, 0]
        for expected, found in zip(actual, predicted):
            index = (0 if label in found else 2) if label in expected else (1 if label in found else 3)
            counts[index] += 1
        tp, fp, fn, tn = counts
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0
        per_label[label] = {
            "precision": precision, "recall": recall, "f1": f1, "support": tp + fn,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "matrix": [[tn, fp], [fn, tp]],
        }
    return {
        "macro_f1": sum(item["f1"] for item in per_label.values()) / len(per_label),
        "per_label": per_label,
    }


def evaluate(model, rows):
    actual = [set(row["target"]) for row in rows]
    predicted = [{label for label, *_ in predict(model, row["content"])} for row in rows]
    actual_owasp = [
        {code for label in labels for code in categories(label, row["is_api"])}
        for labels, row in zip(actual, rows)
    ]
    predicted_owasp = [
        {code for label in labels for code in categories(label, row["is_api"])}
        for labels, row in zip(predicted, rows)
    ]
    assessed = sorted({code for codes in actual_owasp for code in codes})
    return {
        "n": len(rows),
        "patterns": measure(actual, predicted, LABELS),
        "owasp": measure(actual_owasp, predicted_owasp, assessed),
        "unassessed_owasp": sorted((WEB.keys() | API.keys()) - set(assessed)),
        "binary": measure(
            [{"vulnerable"} if row else set() for row in actual],
            [{"vulnerable"} if row else set() for row in predicted],
            ["vulnerable"],
        ),
        "errors": [
            {"id": row["id"], "language": row["language"], "project": row["project"],
             "expected": sorted(want), "predicted": sorted(got), "false_positives": sorted(got - want),
             "false_negatives": sorted(want - got)}
            for row, want, got in zip(rows, actual, predicted) if want != got
        ],
    }


def tune(rows, validation, algorithm, parameters):
    candidates = []
    for parameter in parameters:
        model = fit(rows, algorithm, parameter)
        for threshold in (0.45, 0.55, 0.65, 0.75):
            for classifier in model["classifiers"].values():
                classifier["threshold"] = threshold
            result = evaluate(model, validation)
            candidates.append({
                "algorithm": algorithm, "parameter": parameter, "threshold": threshold,
                "macro_f1": result["owasp"]["macro_f1"],
                "false_positives": result["binary"]["per_label"]["vulnerable"]["fp"],
            })
    winner = max(candidates, key=ranking)
    model = fit(rows, algorithm, winner["parameter"])
    for classifier in model["classifiers"].values():
        classifier["threshold"] = winner["threshold"]
    return model, candidates, winner


def ranking(candidate):
    return (candidate["macro_f1"], -candidate["false_positives"],
            -abs(candidate["threshold"] - 0.55), candidate["algorithm"] == "logistic")


def write_matrix(rows, model):
    vocabulary = model["vocabulary"]
    with (ARTIFACTS / "features.csv").open("w", encoding="utf-8", newline="") as outfile:
        writer = csv.writer(outfile, lineterminator="\n")
        writer.writerow(["id", "partition", *vocabulary])
        for row in rows:
            vector = encode(row["features"], model)
            writer.writerow([row["id"], row["partition"], *(round(vector.get(term, 0), 6) for term in vocabulary)])


def run():
    raw = corpus.read()
    rows = corpus.normalize(raw)
    partitions = {name: [row for row in rows if row["partition"] == name] for name in corpus.PROJECTS}
    if len(rows) < 500 or sum(not row["target"] for row in rows) < 100:
        raise ValueError("El conjunto limpio no satisface los mínimos del laboratorio")
    models = {}
    trials = []
    winners = []
    for algorithm, parameters in (("logistic", (0.0005, 0.003, 0.015)),
                                  ("bernoulli", (0.5, 1.0, 2.0))):
        model, candidates, winner = tune(partitions["train"], partitions["validation"], algorithm, parameters)
        models[algorithm] = model
        winners.append(winner)
        trials.extend(candidates)
    selected = max(winners, key=ranking)["algorithm"]
    save_json(DEFAULT_MODEL, models[selected])
    write_matrix(rows, models[selected])
    results = {
        "selected": selected, "selection_rule": "Mayor F1 macro OWASP en validación, menos falsos positivos binarios, "
        "umbral más cercano a 0.55 y regresión logística si persiste el empate",
        "dataset": corpus.describe(raw), "clean_records": len(rows),
        "feature_count": len(models[selected]["vocabulary"]), "trials": trials, "comparison": {},
    }
    for winner in winners:
        algorithm = winner["algorithm"]
        results["comparison"][algorithm] = {
            "configuration": winner,
            **{name: evaluate(models[algorithm], partitions[name]) for name in ("validation", "test")},
        }
    save_json(ARTIFACTS / "metrics.json", results)
    for algorithm, item in results["comparison"].items():
        print(f"{algorithm}: F1 macro OWASP validación {item['validation']['owasp']['macro_f1']:.3f}, "
              f"prueba {item['test']['owasp']['macro_f1']:.3f}")
    print(f"Modelo seleccionado: {selected}")
    return results


if __name__ == "__main__":
    run()
