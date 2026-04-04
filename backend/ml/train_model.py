"""
PhishGuard -- ml/train_model.py
Train a Random Forest classifier on the phishing URL dataset.

Usage:
    cd backend
    python ml/train_model.py

Output:
    ml/model.pkl  -- trained model file (auto-loaded by detector.py)
"""

import os
import sys
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Add parent directory so we can import features
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.extractor import extract_features, _feature_names


def load_dataset(csv_path):
    """Load URL dataset from CSV file."""
    print(f"\n[1/5] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"      Total samples: {len(df)}")
    print(f"      Safe URLs:     {len(df[df['label'] == 0])}")
    print(f"      Phishing URLs: {len(df[df['label'] == 1])}")
    return df


def extract_all_features(df):
    """Extract features from all URLs in the dataset."""
    print(f"\n[2/5] Extracting {len(_feature_names())} features from {len(df)} URLs...")
    
    feature_list = []
    for i, row in df.iterrows():
        url = row["url"]
        features = extract_features(url)
        feature_vector = [features.get(k, 0) for k in _feature_names()]
        feature_list.append(feature_vector)
        
        # Progress indicator
        if (i + 1) % 50 == 0:
            print(f"      Processed {i + 1}/{len(df)} URLs")
    
    X = np.array(feature_list)
    y = df["label"].values
    
    print(f"      Feature matrix shape: {X.shape}")
    return X, y


def train_model(X, y):
    """Train Random Forest classifier."""
    print(f"\n[3/5] Splitting dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train)} | Test: {len(X_test)}")
    
    print(f"\n[4/5] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*50}")
    print(f"  MODEL EVALUATION RESULTS")
    print(f"{'='*50}")
    print(f"\n  Accuracy: {accuracy * 100:.1f}%\n")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    
    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted Safe  Predicted Phishing")
    print(f"  Actual Safe       {cm[0][0]:>5}          {cm[0][1]:>5}")
    print(f"  Actual Phishing   {cm[1][0]:>5}          {cm[1][1]:>5}")
    
    # Feature importance
    print(f"\n  Top 10 Most Important Features:")
    importances = model.feature_importances_
    names = _feature_names()
    feature_imp = sorted(zip(names, importances), key=lambda x: x[1], reverse=True)
    for name, imp in feature_imp[:10]:
        bar = "#" * int(imp * 50)
        print(f"    {name:30s} {imp:.3f}  {bar}")
    
    return model


def save_model(model, save_path):
    """Save trained model to pickle file."""
    print(f"\n[5/5] Saving model to: {save_path}")
    with open(save_path, "wb") as f:
        pickle.dump(model, f)
    
    size_kb = os.path.getsize(save_path) / 1024
    print(f"      Model size: {size_kb:.1f} KB")
    print(f"\n{'='*50}")
    print(f"  Model trained and saved successfully!")
    print(f"  The API will auto-load model.pkl on next start.")
    print(f"{'='*50}\n")


def main():
    # Paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, "dataset.csv")
    model_path = os.path.join(script_dir, "model.pkl")
    
    # Check dataset exists
    if not os.path.exists(csv_path):
        print(f"Error: Dataset not found at {csv_path}")
        print("Please create ml/dataset.csv with columns: url, label")
        sys.exit(1)
    
    # Pipeline
    df = load_dataset(csv_path)
    X, y = extract_all_features(df)
    model = train_model(X, y)
    save_model(model, model_path)


if __name__ == "__main__":
    main()
