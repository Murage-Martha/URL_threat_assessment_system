import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from app.models.ml_model import URLThreatModel
import os
from datetime import datetime

def train_and_save_model():
    print("Loading dataset from malicious_phish_small.csv...")
    try:
        # Load the smaller dataset
        df = pd.read_csv('malicious_phish_small.csv')
        
        # Check for 'url' and 'label' columns
        if 'url' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'url' and 'label' columns")
        
        # Convert labels to binary
        df['binary_label'] = df['label'].apply(
            lambda x: 1 if x.lower() in ['malicious', 'phishing', 'malware', 'bad'] else 0
        )
        
        # Extract URLs and labels
        urls = df['url'].tolist()
        labels = df['binary_label'].tolist()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(urls, labels, test_size=0.2, random_state=42)
        
        # Initialize model
        model = URLThreatModel()
        
        # Train model
        print("Training model...")
        model.train(X_train, y_train)
        
        # Evaluate on test set
        correct = 0
        for url, true_label in zip(X_test, y_test):
            status, score = model.predict(url)
            predicted_label = 1 if status in ['malicious', 'suspicious'] else 0
            if predicted_label == true_label:
                correct += 1
        
        accuracy = correct / len(X_test)
        print(f"Model accuracy on test set: {accuracy:.4f}")
        
        # Save model
        model_dir = 'app/models/saved_models'
        os.makedirs(model_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = f"{model_dir}/url_threat_model_{timestamp}.joblib"
        model.save_model(model_path)
        
        # Create a symlink to the latest model
        latest_model_path = f"{model_dir}/latest_model.joblib"
        if os.path.exists(latest_model_path):
            os.remove(latest_model_path)
        os.symlink(os.path.abspath(model_path), latest_model_path)
        
        print(f"Model saved to {model_path}")
        print(f"Latest model symlink created at {latest_model_path}")
        
        return model_path
        
    except Exception as e:
        print(f"Error training model: {str(e)}")
        raise

def test_model(model_path, test_urls=None):
    """Test the trained model on some example URLs"""
    print(f"\nTesting model from {model_path}")
    model = URLThreatModel(model_path=model_path)
    
    if not test_urls:
        test_urls = [
            "https://www.google.com",
            "https://www.facebook.com", 
            "http://malware.testing.google.test/testing/malware/",
            "http://bank-secure-login.com.phishing.ru/login",
            "http://paypal.com.secure-update.credential.info/login.php"
        ]
    
    for url in test_urls:
        status, score = model.predict(url)
        print(f"URL: {url}")
        print(f"Prediction: {status} (score: {score:.4f})")
        print("-" * 50)

if __name__ == "__main__":
    model_path = train_and_save_model()
    test_model(model_path) 