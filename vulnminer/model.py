"""Inferencia sobre un artefacto JSON portable, sin cargar objetos ejecutables."""

import json
import math
from pathlib import Path

from .catalog import LABELS
from .features import FEATURE_VERSION, eligible, features

MODEL_VERSION = 1
DEFAULT_MODEL = Path(__file__).with_name("model.json")


def sigmoid(logit):
    return 1 / (1 + math.exp(-max(-40, min(logit, 40))))


def load_model(path=DEFAULT_MODEL):
    model = json.loads(Path(path).read_text(encoding="utf-8"))
    if (model.get("version") != MODEL_VERSION
            or model.get("feature_version") != FEATURE_VERSION
            or set(model.get("classifiers", {})) != set(LABELS)):
        raise ValueError("El modelo no es compatible con esta versión de VulnMiner")
    return model


def vectorize(raw, vocabulary):
    matched = sorted(raw & vocabulary.keys())
    norm = math.sqrt(sum(vocabulary[item] ** 2 for item in matched)) or 1
    return {item: vocabulary[item] / norm for item in matched}


def encode(raw, model):
    vocabulary = model["vocabulary"]
    if model["algorithm"] == "logistic":
        return vectorize(raw, vocabulary)
    return dict.fromkeys(sorted(raw & vocabulary.keys()), 1)


def predict(model, text, include_pending=False):
    if not eligible(text):
        return []
    values = encode(features(text), model)
    results = []
    for label, classifier in model["classifiers"].items():
        positive = []
        score = classifier["intercept"]
        for feature, value in values.items():
            contribution = classifier["weights"].get(feature, 0) * value
            score += contribution
            if contribution > 0 and feature.startswith(("a:", "c:")):
                positive.append((contribution, feature[2:]))
        confidence = sigmoid(score)
        if not positive:
            continue
        threshold = classifier["threshold"]
        if confidence >= threshold or (include_pending and confidence >= model["review_floor"] and confidence > threshold - 0.15):
            signals = [signal for _, signal in sorted(positive, reverse=True)[:4]]
            results.append((label, confidence, confidence >= threshold, signals))
    return sorted(results, key=lambda result: (-result[1], result[0]))
