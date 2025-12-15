from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_PATH = "models/urlbert-multiclass"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

print("✅ Model ready for inference")
