import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import re
from typing import List, Tuple
from urllib.parse import urlparse

class URLFeatureExtractor:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
        
    def extract_url_features(self, url: str) -> List[float]:
        # Extract basic features from URL
        parsed = urlparse(url)
        
        features = {
            'length': len(url),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special': len(re.findall(r'[^a-zA-Z0-9.]', url)),
            'has_https': int(parsed.scheme == 'https'),
            'num_dots': url.count('.'),
            'num_subdomains': len(parsed.netloc.split('.')) - 1,
            'path_length': len(parsed.path),
            'has_suspicious_words': int(bool(re.search(r'login|admin|backup|update|secure|account', url.lower())))
        }
        
        return list(features.values())

class URLThreatModel:
    def __init__(self, model_path: str = None):
        self.feature_extractor = URLFeatureExtractor()
        self.model = RandomForestClassifier() if not model_path else joblib.load(model_path)
        self.is_trained = False if not model_path else True
    
    def train(self, urls: List[str], labels: List[int]):
        """Train the model with example URLs"""
        # Extract features
        print("Extracting features from URLs...")
        features = []
        for i, url in enumerate(urls):
            if i % 1000 == 0:
                print(f"Processed {i}/{len(urls)} URLs...")
            features.append(self.feature_extractor.extract_url_features(url))
        
        # Train model with limited estimators for faster results
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(n_estimators=50, n_jobs=-1, random_state=42)
        self.model.fit(features, labels)
        self.is_trained = True
        
    def predict(self, url: str) -> Tuple[str, float]:
        """Predict if a URL is malicious"""
        if not self.is_trained:
            raise ValueError("Model needs to be trained or loaded first")
        
        # Extract features
        features = self.feature_extractor.extract_url_features(url)
        
        # Make prediction
        probability = self.model.predict_proba([features])[0]
        threat_score = probability[1]  # Probability of malicious class
        
        # Classify based on threat score
        if threat_score < 0.3:
            status = "safe"
        elif threat_score < 0.7:
            status = "suspicious"
        else:
            status = "malicious"
            
        return status, float(threat_score)
    
    def save_model(self, path: str):
        """Save the trained model"""
        if not self.is_trained:
            raise ValueError("Model needs to be trained before saving")
        joblib.dump(self.model, path)