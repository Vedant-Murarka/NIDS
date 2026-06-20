import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

print("1. Loading dataset...")
data_path = r"data/Kaggle-UNSW-NB15-V2/Kaggle-UNSW-NB15-V2/NF-UNSW-NB15-V2.parquet"
df = pd.read_parquet(data_path)
print(f"Loaded {df.shape[0]} rows and {df.shape[1]} columns.")

print("2. Mapping labels...")
# Set target label
df['label'] = df['Attack'].fillna('Benign').astype(str).str.strip()

print("3. Dropping leakage and target columns...")
# Columns to drop to prevent environment and target leakage
cols_to_drop = [
    'IPV4_SRC_ADDR', 'IPV4_DST_ADDR',  # IP addresses (if any)
    'L4_SRC_PORT', 'L4_DST_PORT',      # Source/Dest Ports
    'Label', 'Attack', 'label'         # Target columns
]

X = df.drop(columns=[col for col in cols_to_drop if col in df.columns], errors='ignore')
y = df['label']

feature_names = X.columns.tolist()
print(f"Features list ({len(feature_names)}): {feature_names}")

# Encode target classes
print("4. Encoding target...")
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"Classes found: {list(le.classes_)}")

# Subsample for fast local training (500,000 rows is highly representative for high-accuracy local deployment)
print("5. Subsampling and splitting data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, train_size=500000, test_size=100000, random_state=42, stratify=y_encoded
)

print(f"Training set shape: {X_train.shape}, Test set shape: {X_test.shape}")

# Train the Random Forest
print("6. Training Random Forest model (this may take 10-15 seconds)...")
rf = RandomForestClassifier(
    n_estimators=60,
    max_depth=18,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train, y_train)

# Evaluate the model
print("7. Evaluating model on test split...")
y_pred = rf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

# Save the model components
print("8. Saving model, label encoder, and feature names to disk...")
model_data = {
    'model': rf,
    'label_encoder': le,
    'feature_names': feature_names
}
joblib.dump(model_data, 'nids_model.joblib')
print("Model saved successfully as 'nids_model.joblib'!")
