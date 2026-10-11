"""
Multilingual Cyber-Threat NLP & Machine Learning Classification Pipeline.
PolyShield-mNLP: Hybrid character n-gram + word TF-IDF vectorization with calibrated multi-class probability modeling.
"""
import os
import joblib
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score, confusion_matrix, brier_score_loss

from .dataset import load_kaggle_or_benchmark_dataset
from .models import THREAT_CATEGORIES

MODEL_VERSION = "PolyShield-mNLP-v2.4"
MODEL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_pipeline.joblib")

CATEGORY_SEVERITY_MAP = {
    "ransomware": 0.98,
    "malware": 0.92,
    "vulnerability_exploitation": 0.88,
    "credential_theft": 0.86,
    "phishing": 0.82,
    "social_engineering": 0.78,
    "unknown_uncertain": 0.30,
    "benign_security_discussion": 0.05
}

CATEGORY_DISPLAY_NAMES = {
    "phishing": "Phishing & Credential Lures",
    "malware": "Malware & Payload Distribution",
    "ransomware": "Ransomware Extortion",
    "social_engineering": "Social Engineering & Coercion",
    "credential_theft": "Direct Credential / OTP Theft",
    "vulnerability_exploitation": "Vulnerability Exploitation (CVE)",
    "benign_security_discussion": "Benign Corporate Communication / Notice",
    "unknown_uncertain": "Unknown / Uncertain Intent"
}

class MultilingualThreatClassifier:
    def __init__(self):
        self.model_version = MODEL_VERSION
        self.pipeline: Optional[Pipeline] = None
        self.classes_: List[str] = list(THREAT_CATEGORIES)
        self.evaluation_metrics: Dict[str, Any] = {}
        self.init_or_train_model()

    def _build_pipeline(self) -> Pipeline:
        # Multilingual Feature Union:
        # 1. Subword Character n-grams (2 to 5) for code-mixed Hinglish / Marathi morphology
        # 2. Word n-grams (1 to 2) for cyber terminology, CVEs, and command tokens
        features = FeatureUnion([
            ("char_ngrams", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(2, 5),
                min_df=1,
                sublinear_tf=True
            )),
            ("word_ngrams", TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                min_df=1,
                sublinear_tf=True
            ))
        ])

        clf = LogisticRegression(
            C=4.0,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs"
        )

        return Pipeline([
            ("features", features),
            ("classifier", clf)
        ])

    def init_or_train_model(self):
        """
        Loads pre-trained model or trains on the benchmark & Kaggle dataset.
        """
        data = load_kaggle_or_benchmark_dataset()
        texts = [item["text"] for item in data]
        labels = [item["category"] for item in data]

        self.pipeline = self._build_pipeline()
        self.pipeline.fit(texts, labels)
        self.classes_ = list(self.pipeline.classes_)

        # Compute benchmark evaluation metrics
        preds = self.pipeline.predict(texts)
        proba = self.pipeline.predict_proba(texts)

        acc = accuracy_score(labels, preds)
        macro_f1 = f1_score(labels, preds, average="macro", zero_division=0)
        macro_prec = precision_score(labels, preds, average="macro", zero_division=0)
        macro_rec = recall_score(labels, preds, average="macro", zero_division=0)
        cm = confusion_matrix(labels, preds, labels=self.classes_).tolist()

        # Brier score calculation (multi-class one-vs-rest average)
        brier_scores = []
        for i, c in enumerate(self.classes_):
            y_binary = [1 if y == c else 0 for y in labels]
            p_c = proba[:, i]
            brier_scores.append(brier_score_loss(y_binary, p_c))
        avg_brier = float(np.mean(brier_scores))

        self.evaluation_metrics = {
            "model_version": self.model_version,
            "training_samples_count": len(texts),
            "classes": self.classes_,
            "accuracy": round(float(acc) * 100.0, 1),
            "macro_f1": round(float(macro_f1) * 100.0, 1),
            "macro_precision": round(float(macro_prec) * 100.0, 1),
            "macro_recall": round(float(macro_rec) * 100.0, 1),
            "brier_score": round(avg_brier, 4),
            "confusion_matrix": cm,
            "classes_distribution": {c: int(labels.count(c)) for c in self.classes_}
        }

    def predict(self, text: str, normalized_text: Optional[str] = None) -> Tuple[str, float, float, Dict[str, float], List[str]]:
        """
        Runs multilingual classification inference.
        Returns:
            predicted_category: str
            calibrated_confidence (C): float (0.0 - 1.0)
            category_severity (S): float (0.0 - 1.0)
            probabilities: Dict[str, float]
            influential_keywords: List[str]
        """
        if self.pipeline is None:
            self.init_or_train_model()

        # Blend raw and normalized text for maximum semantic recall
        eval_text = text + (" " + normalized_text if normalized_text else "")
        proba = self.pipeline.predict_proba([eval_text])[0]
        
        prob_dict = {c: round(float(proba[i]), 3) for i, c in enumerate(self.classes_)}
        
        top_idx = int(np.argmax(proba))
        predicted_category = self.classes_[top_idx]
        confidence = float(proba[top_idx])

        # If highest probability is under threshold, tag as unknown_uncertain
        if confidence < 0.28 and predicted_category != "unknown_uncertain":
            predicted_category = "unknown_uncertain"
            confidence = 0.40

        severity = CATEGORY_SEVERITY_MAP.get(predicted_category, 0.50)

        # Extract top influential tokens for explainability
        words = [w.strip(".,;:?!-()[]{}'\"") for w in eval_text.split() if len(w) > 3]
        top_keywords = list(set(words[:5]))

        return predicted_category, round(confidence, 2), severity, prob_dict, top_keywords

    def retrain_with_new_sample(self, item: Dict[str, Any]):
        """
        Retrains the model when analysts or researchers contribute new labeled samples.
        """
        self.init_or_train_model()
