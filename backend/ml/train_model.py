"""
PhishGuard -- ml/train_model.py
Industrial-Grade ML Training Pipeline (RandomForest + 50K URLs)

Uses scikit-learn RandomForest (no xgboost dependency) for maximum
compatibility across all deployment platforms.

Usage:
    cd backend
    python ml/train_model.py
"""

import os
import sys
import pickle
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.extractor import extract_features, _feature_names


def load_dataset():
    """Download UCI PhiUSIIL dataset."""
    print("\n  Downloading UCI PhiUSIIL Phishing URL Dataset...")
    try:
        from ucimlrepo import fetch_ucirepo
        dataset = fetch_ucirepo(id=967)
        X_df = dataset.data.features
        y_df = dataset.data.targets
        for col in ["URL", "url", "Url"]:
            if col in X_df.columns:
                urls = X_df[col].tolist()
                labels = y_df.values.ravel()
                print(f"  Loaded {len(urls)} URLs")
                return urls, labels
        return X_df, y_df
    except Exception as e:
        print(f"  UCI download failed: {e}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        df = pd.read_csv(os.path.join(script_dir, "dataset.csv"))
        return df["url"].tolist(), df["label"].values


def extract_all_features(urls, labels, max_samples=50000):
    """Extract 30 features from URLs."""
    if isinstance(urls, pd.DataFrame):
        X = np.nan_to_num(urls.values.astype(float), nan=0.0)
        y = labels.values.ravel() if hasattr(labels, 'values') else labels
        return X, y

    total = len(urls)
    if total > max_samples:
        print(f"\n[2/6] Sampling {max_samples} from {total} URLs (balanced)...")
        labs = np.array(labels)
        phish_idx = np.where(labs == 1)[0]
        safe_idx = np.where(labs == 0)[0]
        half = max_samples // 2
        rng = np.random.RandomState(42)
        if len(phish_idx) >= half and len(safe_idx) >= half:
            indices = np.concatenate([
                rng.choice(phish_idx, half, replace=False),
                rng.choice(safe_idx, half, replace=False)
            ])
        else:
            indices = rng.choice(total, max_samples, replace=False)
        rng.shuffle(indices)
        urls = [urls[i] for i in indices]
        labels = labs[indices]
    else:
        print(f"\n[2/6] Extracting features from {total} URLs...")

    feature_names = _feature_names()
    feature_list = []
    errors = 0
    start = time.time()

    for i, url in enumerate(urls):
        try:
            features = extract_features(str(url))
            feature_list.append([features.get(k, 0) for k in feature_names])
        except Exception:
            feature_list.append([0] * len(feature_names))
            errors += 1
        if (i + 1) % 2500 == 0 or (i + 1) == len(urls):
            elapsed = time.time() - start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"      [{(i+1)/len(urls)*100:5.1f}%] {i+1}/{len(urls)}  "
                  f"({rate:.0f}/sec, errors: {errors})")

    X = np.array(feature_list, dtype=np.float32)
    y = labels[:len(feature_list)]
    print(f"      Shape: {X.shape} | Phishing: {sum(y==1)} | Safe: {sum(y==0)}")
    return X, y


def train_model(X, y):
    """Train RandomForest classifier."""
    X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
    mask = X.sum(axis=1) != 0
    X, y = X[mask], y[mask]

    print(f"\n[3/6] Splitting 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[4/6] Training RandomForest (300 trees)...")
    start = time.time()
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print(f"      Done in {time.time()-start:.1f}s")

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    auc       = roc_auc_score(y_test, y_proba)

    print(f"\n{'='*60}")
    print(f"  MODEL RESULTS (RandomForest)")
    print(f"{'='*60}")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"  AUC-ROC:   {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"  {'':20s} Pred Safe  Pred Phish")
    print(f"  {'Actual Safe':20s}  {cm[0][0]:>7}     {cm[0][1]:>7}")
    print(f"  {'Actual Phishing':20s}  {cm[1][0]:>7}     {cm[1][1]:>7}")

    names = _feature_names()
    if len(names) == X.shape[1]:
        imp = sorted(zip(names, model.feature_importances_), key=lambda x: x[1], reverse=True)
        print(f"\n  Top 10 Features:")
        for n, v in imp[:10]:
            print(f"    {n:25s} {v:.4f}  {'#'*int(v*50)}")

    print(f"\n  10-Fold CV...")
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    print(f"  CV: {cv_scores.mean()*100:.2f}% +/- {cv_scores.std()*100:.2f}%")

    return model, {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "auc_roc": auc,
        "cv_mean": cv_scores.mean(), "cv_std": cv_scores.std(),
    }


def save_model(model, metrics, path):
    print(f"\n[6/6] Saving to {path}")
    data = {
        "model": model,
        "model_type": "RandomForestClassifier",
        "n_features": 30,
        "feature_names": _feature_names(),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": "UCI PhiUSIIL (50K balanced)",
        **metrics,
    }
    with open(path, "wb") as f:
        pickle.dump(data, f)
    print(f"      Size: {os.path.getsize(path)/1024:.1f} KB")
    print(f"      Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"\n  Model saved successfully!\n")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "model.pkl")
    print("\n" + "="*60)
    print("  PhishGuard ML Training v3.0")
    print("  RandomForest + 30 Features + 50K URLs")
    print("="*60)
    print(f"\n[1/6] Loading dataset...")
    urls, labels = load_dataset()
    X, y = extract_all_features(urls, labels, max_samples=50000)
    model, metrics = train_model(X, y)
    save_model(model, metrics, model_path)


if __name__ == "__main__":
    main()
