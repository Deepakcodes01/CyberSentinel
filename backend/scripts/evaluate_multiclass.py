import pandas as pd
import torch
from tqdm import tqdm
from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ----------------------------
# Model path
# ----------------------------
MODEL_PATH = "models/urlbert-multiclass"

id2label = {
    0: "benign",
    1: "phishing",
    2: "defacement",
    3: "malware",
}
label2id = {v: k for k, v in id2label.items()}

# ----------------------------
# Load model & tokenizer
# ----------------------------
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()

# ----------------------------
# Load dataset
# ----------------------------
df = pd.read_csv("data/malicious_phish.csv")

# Sample for fast demo (VERY IMPORTANT)
df = df.sample(5000, random_state=42)

y_true = df["type"].map(label2id).values
y_pred = []

print("\n🔍 Starting MULTI-CLASS model evaluation")
print(f"📂 Total samples: {len(df)}\n")

# ----------------------------
# Inference with progress bar
# ----------------------------
for url in tqdm(df["url"], desc="🤖 Evaluating URLs", unit="url"):
    inputs = tokenizer(str(url), return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)

    pred_class = torch.argmax(outputs.logits, dim=1).item()
    y_pred.append(pred_class)

# ----------------------------
# Metrics
# ----------------------------
print("\n📊 MULTI-CLASS CLASSIFICATION REPORT\n")
print(classification_report(
    y_true,
    y_pred,
    target_names=id2label.values(),
))

print("🧮 CONFUSION MATRIX\n")
print(confusion_matrix(y_true, y_pred))
