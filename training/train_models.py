"""
Model Training and Evaluation Pipeline:
Trains Isolation Forest (unsupervised anomaly detector) and Random Forest (classifier),
computes comprehensive evaluation metrics (Accuracy, Precision, Recall, F1, FPR),
and persists the trained models for real-time inference.
"""
import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

from config.settings import MODELS_DIR, ISOLATION_FOREST_PATH, RANDOM_FOREST_PATH, SCALER_PATH
from features.schema import FEATURE_NAMES, ATTACK_CLASSES, CLASS_TO_ID, ID_TO_CLASS
from training.prepare_benchmark_data import generate_benchmark_dataset, OUTPUT_CSV

def train_and_save_models():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 65)
    if not OUTPUT_CSV.exists():
        print(">> Benchmark dataset not found. Generating canonical dataset...")
        df = generate_benchmark_dataset()
    else:
        print(f">> Loading verified benchmark dataset: {OUTPUT_CSV}...")
        df = pd.read_csv(OUTPUT_CSV)

    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = np.array([CLASS_TO_ID[label] for label in df["label"]], dtype=np.int64)
    print(f">> Dataset loaded: {X.shape[0]} flows, {X.shape[1]} features across {len(ATTACK_CLASSES)} classes.")

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )


    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, SCALER_PATH)
    print(f">> Feature scaler saved to: {SCALER_PATH}")

    # =========================================================================
    # 1. Train Isolation Forest (Trained primarily on Benign traffic)
    # =========================================================================
    print("\n" + "=" * 65)
    print(">> Training Unsupervised Isolation Forest (Anomaly Detector)...")
    benign_idx = (y_train == CLASS_TO_ID["BENIGN"])
    X_train_benign = X_train_scaled[benign_idx]

    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.04,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train_benign)
    joblib.dump(iso_forest, ISOLATION_FOREST_PATH)
    print(f">> Isolation Forest model saved to: {ISOLATION_FOREST_PATH}")

    # Evaluate Isolation Forest on binary task (Benign vs Malicious)
    # IsolationForest: 1 -> inlier (normal), -1 -> outlier (anomaly)
    iso_preds = iso_forest.predict(X_test_scaled)
    # Binary ground truth: 0 if Benign, 1 if Any Attack
    y_test_binary = (y_test != CLASS_TO_ID["BENIGN"]).astype(int)
    iso_preds_binary = (iso_preds == -1).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test_binary, iso_preds_binary).ravel()
    iso_acc = accuracy_score(y_test_binary, iso_preds_binary)
    iso_prec = tp / max(1, (tp + fp))
    iso_rec = tp / max(1, (tp + fn))
    iso_f1 = 2 * (iso_prec * iso_rec) / max(1e-6, (iso_prec + iso_rec))
    iso_fpr = fp / max(1, (fp + tn))

    print("\n--- Isolation Forest Anomaly Detection Metrics ---")
    print(f"Accuracy:  {iso_acc * 100:.2f}%")
    print(f"Precision: {iso_prec * 100:.2f}%")
    print(f"Recall:    {iso_rec * 100:.2f}%")
    print(f"F1-Score:  {iso_f1 * 100:.2f}%")
    print(f"FPR (False Positive Rate): {iso_fpr * 100:.2f}%")
    print(f"Confusion Matrix [TN: {tn}, FP: {fp}, FN: {fn}, TP: {tp}]")

    # =========================================================================
    # 2. Train Random Forest Classifier (Supervised Attack Classifier)
    # =========================================================================
    print("\n" + "=" * 65)
    print(">> Training Random Forest Classifier (Multi-Class Attack Classifier)...")
    rf_clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    rf_clf.fit(X_train_scaled, y_train)
    joblib.dump(rf_clf, RANDOM_FOREST_PATH)
    print(f">> Random Forest model saved to: {RANDOM_FOREST_PATH}")

    rf_preds = rf_clf.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    print("\n--- Random Forest Multi-Class Report ---")
    print(f"Overall Accuracy: {rf_acc * 100:.2f}%\n")
    print(classification_report(y_test, rf_preds, target_names=ATTACK_CLASSES, digits=4))

    # Calculate feature importances
    importances = rf_clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("--- Top 5 Most Informative Flow Features ---")
    for rank, idx in enumerate(sorted_idx[:5], 1):
        print(f"{rank}. {FEATURE_NAMES[idx]}: {importances[idx]:.4f}")

    print("=" * 65)
    print(">> Model training and validation complete!")
    return {
        "isolation_forest": {
            "accuracy": iso_acc,
            "precision": iso_prec,
            "recall": iso_rec,
            "f1": iso_f1,
            "fpr": iso_fpr
        },
        "random_forest": {
            "accuracy": rf_acc
        }
    }

if __name__ == "__main__":
    train_and_save_models()
