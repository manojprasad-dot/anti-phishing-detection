"""
PhishGuard -- ml/train_model.py
Industrial-Grade ML Training Pipeline

Trains a Random Forest classifier on the UCI PhiUSIIL Phishing URL Dataset
(235,795 URLs) — one of the largest, most cited phishing datasets in academia.

Dataset: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website
Paper:   PhiUSIIL: A Diverse Security Profile Empowered Phishing URL Detection

Usage:
    cd backend
    python ml/train_model.py

Output:
    ml/model.pkl  -- trained model (auto-loaded by detector.py)
"""

import os
import sys
import pickle
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler

# Add parent directory so we can import features
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.extractor import extract_features, _feature_names


# ═══════════════════════════════════════════════════════════════════
# STEP 1: LOAD DATASET
# ═══════════════════════════════════════════════════════════════════
def load_dataset():
    """
    Try multiple dataset sources in order:
    1. Local dataset.csv (custom URLs)
    2. UCI PhiUSIIL dataset (235K URLs — downloaded automatically)
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, "dataset.csv")

    # Try local CSV first
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        if len(df) > 500:
            print(f"  [Local] Loaded {len(df)} URLs from dataset.csv")
            return df["url"].tolist(), df["label"].values

    # Download UCI PhiUSIIL dataset
    print("  Downloading UCI PhiUSIIL Phishing URL Dataset...")
    print("  (235,795 URLs — this may take a minute)\n")

    try:
        from ucimlrepo import fetch_ucirepo
        dataset = fetch_ucirepo(id=967)
        X_df = dataset.data.features
        y_df = dataset.data.targets

        # The dataset has a 'URL' column and a 'label' column
        # label: 0 = legitimate, 1 = phishing
        if "URL" in X_df.columns:
            urls = X_df["URL"].tolist()
        elif "url" in X_df.columns:
            urls = X_df["url"].tolist()
        else:
            # Dataset has pre-extracted features, use them directly
            print(f"  UCI dataset loaded with {len(X_df)} samples, {len(X_df.columns)} features")
            return X_df, y_df

        labels = y_df.values.ravel()
        print(f"  UCI dataset loaded: {len(urls)} URLs")
        return urls, labels

    except Exception as e:
        print(f"  UCI download failed: {e}")
        print("  Falling back to local dataset.csv")
        df = pd.read_csv(csv_path)
        return df["url"].tolist(), df["label"].values


# ═══════════════════════════════════════════════════════════════════
# STEP 2: EXTRACT FEATURES
# ═══════════════════════════════════════════════════════════════════
def extract_all_features(urls, labels, max_samples=10000):
    """
    Extract our 23 URL features from each URL.
    For very large datasets, sample to keep training fast.
    """
    # If dataset is pre-extracted features (DataFrame), use directly
    if isinstance(urls, pd.DataFrame):
        print(f"\n[2/5] Using pre-extracted features: {urls.shape}")
        X = urls.values.astype(float)
        y = labels.values.ravel() if hasattr(labels, 'values') else labels

        # Handle NaN values
        X = np.nan_to_num(X, nan=0.0)
        return X, y

    total = len(urls)

    # Sample if dataset is too large (for faster training)
    if total > max_samples:
        print(f"\n[2/5] Sampling {max_samples} from {total} URLs for training...")
        indices = np.random.RandomState(42).choice(total, max_samples, replace=False)
        urls = [urls[i] for i in indices]
        labels = labels[indices]
    else:
        print(f"\n[2/5] Extracting features from {total} URLs...")

    feature_names = _feature_names()
    feature_list = []
    errors = 0

    for i, url in enumerate(urls):
        try:
            features = extract_features(str(url))
            vector = [features.get(k, 0) for k in feature_names]
            feature_list.append(vector)
        except Exception:
            feature_list.append([0] * len(feature_names))
            errors += 1

        # Progress
        if (i + 1) % 500 == 0 or (i + 1) == len(urls):
            pct = (i + 1) / len(urls) * 100
            print(f"      [{pct:5.1f}%] Processed {i+1}/{len(urls)} URLs  (errors: {errors})")

    X = np.array(feature_list)
    y = labels[:len(feature_list)]

    print(f"      Feature matrix: {X.shape}")
    return X, y


# ═══════════════════════════════════════════════════════════════════
# STEP 3: TRAIN MODEL
# ═══════════════════════════════════════════════════════════════════
def train_model(X, y):
    """Train Random Forest with optimized hyperparameters."""

    print(f"\n[3/5] Splitting dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train)} | Test: {len(X_test)}")
    print(f"      Train phishing: {sum(y_train == 1)} | Train safe: {sum(y_train == 0)}")

    print(f"\n[4/5] Training Random Forest Classifier...")
    print(f"      (200 trees, max_depth=20, optimized for phishing detection)\n")

    start = time.time()

    model = RandomForestClassifier(
        n_estimators=200,          # More trees = better accuracy
        max_depth=20,              # Deeper trees for complex patterns
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",   # Handle class imbalance
        random_state=42,
        n_jobs=-1                  # Use all CPU cores
    )
    model.fit(X_train, y_train)

    elapsed = time.time() - start
    print(f"      Training completed in {elapsed:.1f} seconds")

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n{'='*60}")
    print(f"  MODEL EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"\n  Overall Accuracy: {accuracy * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print("  Confusion Matrix:")
    print(f"  {'':20s} Predicted Safe  Predicted Phish")
    print(f"  {'Actual Safe':20s}    {cm[0][0]:>6}         {cm[0][1]:>6}")
    print(f"  {'Actual Phishing':20s}    {cm[1][0]:>6}         {cm[1][1]:>6}")

    # Feature importance
    try:
        feature_names = _feature_names()
        if len(feature_names) == X.shape[1]:
            importances = model.feature_importances_
            feature_imp = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
            print(f"\n  Top 10 Most Important Features:")
            for name, imp in feature_imp[:10]:
                bar = "#" * int(imp * 40)
                print(f"    {name:30s} {imp:.4f}  {bar}")
    except Exception:
        pass

    # Cross-validation
    print(f"\n  5-Fold Cross-Validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"  CV Accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

    print(f"\n{'='*60}")
    return model, accuracy


# ═══════════════════════════════════════════════════════════════════
# STEP 4: SAVE MODEL
# ═══════════════════════════════════════════════════════════════════
def save_model(model, accuracy, save_path):
    """Save trained model and metadata."""
    print(f"\n[5/5] Saving model to: {save_path}")

    model_data = {
        "model": model,
        "accuracy": accuracy,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_features": model.n_features_in_,
        "n_estimators": model.n_estimators,
    }

    with open(save_path, "wb") as f:
        pickle.dump(model_data, f)

    size_kb = os.path.getsize(save_path) / 1024
    print(f"      Model size: {size_kb:.1f} KB")
    print(f"      Accuracy: {accuracy*100:.2f}%")
    print(f"\n{'='*60}")
    print(f"  Model trained and saved successfully!")
    print(f"  Restart the API server to load the new model.")
    print(f"{'='*60}\n")


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "model.pkl")

    print("\n" + "="*60)
    print("  PhishGuard ML Training Pipeline")
    print("  Industrial-grade phishing URL classifier")
    print("="*60)

    # Pipeline
    print(f"\n[1/5] Loading dataset...")
    urls, labels = load_dataset()

    X, y = extract_all_features(urls, labels, max_samples=10000)

    model, accuracy = train_model(X, y)

    save_model(model, accuracy, model_path)


if __name__ == "__main__":
    main()
