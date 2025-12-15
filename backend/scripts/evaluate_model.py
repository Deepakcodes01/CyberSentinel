import pandas as pd
from tqdm import tqdm
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from src.urlbert_infer import predict_url_proba

# ----------------------------
# Load dataset
# ----------------------------
df = pd.read_csv("data/malicious_phish.csv")

# OPTIONAL: sample for faster demo (recommended)
df = df.sample(5000, random_state=42)

# Convert labels to binary
# benign -> 0
# phishing / defacement / malware -> 1
df["label"] = df["type"].apply(lambda x: 0 if x == "benign" else 1)

y_true = df["label"].values
y_pred = []

print("\n🔍 Starting model evaluation...")
print(f"📂 Total samples: {len(df)}\n")

# ----------------------------
# Model inference with progress bar
# ----------------------------
for url in tqdm(df["url"], desc="🤖 Evaluating URLs", unit="url"):
    prob = predict_url_proba(url)
    y_pred.append(1 if prob >= 0.5 else 0)

# ----------------------------
# Metrics
# ----------------------------
accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred)
recall = recall_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)

print("\n📊 MODEL PERFORMANCE")
print("-" * 40)
print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1-score  : {f1:.4f}")

print("\n📋 Classification Report")
print(classification_report(y_true, y_pred, target_names=["Benign", "Malicious"]))

print("🧮 Confusion Matrix")
print(confusion_matrix(y_true, y_pred))
