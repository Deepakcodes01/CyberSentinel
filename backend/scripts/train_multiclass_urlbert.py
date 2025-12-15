import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
)

MODEL_NAME = "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"

label_map = {
    "benign": 0,
    "phishing": 1,
    "defacement": 2,
    "malware": 3,
}

# ----------------------------
# Dataset
# ----------------------------
class URLDataset(Dataset):
    def __init__(self, csv_path, tokenizer):
        df = pd.read_csv(csv_path)
        self.urls = df["url"].tolist()
        self.labels = df["type"].map(label_map).tolist()
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.urls)

    def __getitem__(self, idx):
        enc = self.tokenizer(
            self.urls[idx],
            truncation=True,
            padding="max_length",
            max_length=128,
        )
        enc["labels"] = self.labels[idx]
        return {k: torch.tensor(v) for k, v in enc.items()}

# ----------------------------
# Load model
# ----------------------------
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=4,
)

dataset = URLDataset("data/malicious_phish.csv", tokenizer)

# ----------------------------
# Training arguments
# ----------------------------
training_args = TrainingArguments(
    output_dir="./urlbert-multiclass",
    evaluation_strategy="no",
    per_device_train_batch_size=32,
    num_train_epochs=2,
    learning_rate=2e-5,
    weight_decay=0.01,
    logging_steps=500,
    save_steps=1000,
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
)

trainer.train()

trainer.save_model("./urlbert-multiclass")
tokenizer.save_pretrained("./urlbert-multiclass")
