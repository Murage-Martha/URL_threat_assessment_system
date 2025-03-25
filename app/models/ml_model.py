import re
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
import joblib
import uuid
from scipy.sparse import hstack, csr_matrix, issparse

class URLFeatureExtractor:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=500)

    def fit(self, urls: pd.Series):
        # Convert urls to string series explicitly
        urls = urls.astype(str)
        self.vectorizer.fit(urls)

    def transform(self, urls: pd.Series) -> csr_matrix:
        # Convert urls to string series explicitly
        urls = urls.astype(str)
        
        # Extract custom features
        features = np.vstack(urls.apply(self.extract_features).values)
        
        # Transform URLs using TF-IDF
        tfidf_features = self.vectorizer.transform(urls)
        
        # Combine features
        return hstack([csr_matrix(features), tfidf_features])

    def extract_features(self, url: str) -> np.ndarray:
        url = str(url)  # Ensure url is a string
        features = []
        features.append(len(url))  # Length of URL
        features.append(url.count('.'))  # Number of dots
        features.append(url.count('@'))  # Presence of '@'
        features.append(url.count('-'))  # Presence of '-'
        features.append(1 if 'https' in url else 0)  # Use of HTTPS
        features.append(len(re.findall(r'\d', url)))  # Number of digits
        features.append(len(re.findall(r'[A-Z]', url)))  # Number of uppercase letters
        features.append(len(re.findall(r'[a-z]', url)))  # Number of lowercase letters
        features.append(1 if re.search(r'\b(?:verify|update|login|secure|bank)\b', url, re.IGNORECASE) else 0)  # Presence of phishing keywords
        features.append(1 if re.match(r'http://\d+\.\d+\.\d+\.\d+', url) else 0)  # Presence of IP address
        return np.array(features)

class URLThreatModel:
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.model = RandomForestClassifier(random_state=42)
        self.is_trained = False

    def train(self, urls: pd.Series, labels: pd.Series, model: RandomForestClassifier = None):
        """Train the model with example URLs"""
        # Ensure urls and labels are converted to string and numeric
        urls = urls.astype(str)
        labels = pd.Series(labels).astype(int)
        
        # Fit feature extractor
        self.feature_extractor.fit(urls)
        
        # Transform features
        X = self.feature_extractor.transform(urls)
        y = labels
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Use provided model or default
        if model is not None:
            self.model = model
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Predict and evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model accuracy: {accuracy:.2f}")
        
        # Print classification report for more detailed metrics
        print(classification_report(y_test, y_pred))
        
        self.is_trained = True

    def predict(self, urls: pd.Series) -> np.ndarray:
        """Predict if URLs are malicious"""
        if not self.is_trained:
            raise ValueError("Model needs to be trained or loaded first")
        
        # Ensure urls are converted to string
        urls = urls.astype(str)
        
        X = self.feature_extractor.transform(urls)
        return self.model.predict(X)

    def analyze_url(self, url: str) -> dict:
        """Analyze a single URL"""
        if not self.is_trained:
            raise ValueError("Model needs to be trained or loaded first")
        
        # Ensure url is converted to string
        url = str(url)
        
        X = self.feature_extractor.transform(pd.Series([url]))
        prediction = self.model.predict(X)[0]
        threat_score = self.model.predict_proba(X)[0].max()
        
        return {
            'analysis_id': str(uuid.uuid4()),  # Generate a unique analysis_id
            'threat_status': 'malicious' if prediction == 1 else 'safe',
            'threat_score': threat_score,
            'source': 'ML Model'
        }

    def save_model(self, path: str):
        """Save the trained model and vectorizer"""
        joblib.dump((self.model, self.feature_extractor.vectorizer), path)

    def load_model(self, path: str):
        """Load a trained model and vectorizer"""
        self.model, self.feature_extractor.vectorizer = joblib.load(path)
        self.is_trained = True