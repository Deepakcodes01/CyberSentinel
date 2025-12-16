import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_PATH = "models/urlbert-multiclass"

print("🔄 Loading URLBERT model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()

id2label = {
    0: "benign",
    1: "phishing",
    2: "defacement",
    3: "malware",
}

print("✅ Model loaded successfully")

def predict_url(url: str):
    inputs = tokenizer(url, return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)

    logits = outputs.logits
    pred_id = torch.argmax(logits, dim=1).item()
    confidence = torch.softmax(logits, dim=1)[0][pred_id].item()

    return id2label[pred_id], confidence
