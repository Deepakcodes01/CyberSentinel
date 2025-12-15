from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_NAME = "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"

# Load model & tokenizer
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()

def predict_url_proba(url: str) -> float:
    """
    Predict probability that a URL is malicious.
    Returns a float between 0 and 1.
    """
    # Tokenize
    inputs = tokenizer(url, return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
    # Return probability of class 1 (malicious)
    return float(probs[0][1])
