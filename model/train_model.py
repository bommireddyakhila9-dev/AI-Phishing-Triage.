"""
Model Training & Evaluation Script
Extracts features from labeled URLs, trains and compares multiple classifiers
(RandomForest vs. GradientBoosting), evaluates metrics on held-out test data,
and persists the champion model along with training metrics.
"""

import json
import os
import sys
from typing import Dict, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# Ensure root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from modules.feature_extraction import FEATURE_COLUMNS, batch_extract_features


DATA_PATH = os.path.join(parent_dir, "data", "sample_urls.csv")
MODEL_DIR = os.path.join(parent_dir, "model")
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
COLUMNS_SAVE_PATH = os.path.join(MODEL_DIR, "feature_columns.json")
METRICS_SAVE_PATH = os.path.join(MODEL_DIR, "training_metrics.json")


def load_and_preprocess_dataset(csv_path: str) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Loads labeled URLs CSV and extracts the 20 security features.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    df = pd.read_csv(csv_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset CSV must contain 'url' and 'label' columns.")

    print(f"[*] Loaded {len(df)} URLs from {csv_path}")
    print("[*] Extracting 20 lexical & structural security features...")
    X = batch_extract_features(df["url"].tolist())
    y = df["label"].astype(str)
    return X, y


def train_and_compare_models() -> Dict:
    """
    Trains and compares Random Forest and Gradient Boosting classifiers.
    Saves the best-performing model.
    """
    os.makedirs(MODEL_DIR, exist_ok=True)
    X, y = load_and_preprocess_dataset(DATA_PATH)

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=120, max_depth=12, random_state=42, class_weight="balanced"
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
        ),
    }

    comparison_results = {}
    best_f1 = -1.0
    best_model_name = ""
    best_model = None

    classes = sorted(list(y.unique()))

    for name, clf in models.items():
        print(f"\n[*] Training {name}...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        print(f"    - Accuracy:  {acc:.4f}")
        print(f"    - Precision: {prec:.4f}")
        print(f"    - Recall:    {rec:.4f}")
        print(f"    - F1-Score:  {f1:.4f}")

        comparison_results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "classes": classes,
            "classification_report": report,
        }

        # Select model prioritizing F1 score and high recall on malicious/phishing classes
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = clf

    print(f"\n[+] Champion Model Selected: {best_model_name} (F1 Score: {best_f1:.4f})")

    # Persist the selected model
    joblib.dump(best_model, MODEL_SAVE_PATH)
    print(f"[+] Saved model to {MODEL_SAVE_PATH}")

    # Persist feature columns
    with open(COLUMNS_SAVE_PATH, "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
    print(f"[+] Saved feature columns to {COLUMNS_SAVE_PATH}")

    # Persist training metrics
    metrics_payload = {
        "best_model": best_model_name,
        "classes": classes,
        "feature_count": len(FEATURE_COLUMNS),
        "total_samples": len(X),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "models_evaluated": comparison_results,
    }
    with open(METRICS_SAVE_PATH, "w") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"[+] Saved evaluation metrics to {METRICS_SAVE_PATH}")

    return metrics_payload


if __name__ == "__main__":
    train_and_compare_models()
