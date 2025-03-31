import os
import re
import pandas as pd
import numpy as np
from dotenv import load_dotenv
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import HashingVectorizer
from app.models.ml_model import URLThreatModel
from scipy.sparse import csr_matrix, hstack
import logging
import multiprocessing
from sklearn.preprocessing import StandardScaler
import joblib

def extract_lightweight_features(urls):
    """
    Extremely lightweight feature extraction with minimal computation
    """
    features = np.zeros((len(urls), 5), dtype=np.float32)
    
    for i, url in enumerate(urls):
        features[i, 0] = len(url)  # URL length
        features[i, 1] = sum(c in '-_@?%/' for c in url)  # Special chars
        features[i, 2] = int('https' in url)  # HTTPS check
        features[i, 3] = sum(c.isdigit() for c in url)  # Numeric chars
        features[i, 4] = int(bool(re.search(r'login|bank|secure', url)))  # Sensitive words
    
    return features

def sample_data(X, y, max_samples=100000):
    """
    Efficiently sample data to reduce training time and memory usage
    """
    if X.shape[0] > max_samples:
        # Stratified sampling
        unique_labels = np.unique(y)
        samples_per_class = max_samples // len(unique_labels)
        
        sampled_indices = []
        for label in unique_labels:
            label_indices = np.where(y == label)[0]
            class_samples = np.random.choice(
                label_indices, 
                min(samples_per_class, len(label_indices)), 
                replace=False
            )
            sampled_indices.extend(class_samples)
        
        # Shuffle sampled indices
        np.random.shuffle(sampled_indices)
        
        return X[sampled_indices], y[sampled_indices]
    
    return X, y

def train_model():
    load_dotenv()
    
    # Minimal logging
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logging.info("Starting URL threat model training")
    
    # Set up paths
    data_file = os.getenv('DATASET_PATH', 'malicious_phish.csv')
    model_dir = 'models'
    model_path = os.path.join(model_dir, 'url_threat_model.joblib')
    vectorizer_path = os.path.join(model_dir, 'url_vectorizer.joblib')
    
    # Create model directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    try:
        # Read dataset efficiently
        logging.info(f"Loading dataset from {data_file}")
        df = pd.read_csv(data_file, usecols=['url', 'label'])
        
        # Preprocess labels
        df['label'] = df['label'].apply(lambda x: 0 if str(x).lower() in ['benign', 'safe'] else 1)
        
        logging.info(f"Total entries: {len(df)}")
        
        # Extract lightweight features
        logging.info("Extracting lightweight features")
        lexical_features = extract_lightweight_features(df['url'].values)
        
        # Use HashingVectorizer with reduced complexity
        logging.info("Vectorizing URLs")
        vectorizer = HashingVectorizer(
            analyzer='char', 
            ngram_range=(3, 4), 
            n_features=2000,
            alternate_sign=False
        )
        url_features = vectorizer.transform(df['url'])
        
        # Combine features
        logging.info("Combining features")
        X = hstack([
            csr_matrix(lexical_features), 
            url_features
        ])
        y = df['label'].values
        
        # Sample data to reduce training time
        X, y = sample_data(X, y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=0.2, 
            random_state=42, 
            stratify=y
        )
        
        # Scale features
        scaler = StandardScaler(with_mean=False)
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Use LogisticRegression with limited CPU usage
        logging.info("Training model")
        clf = LogisticRegression(
            max_iter=300,
            solver='saga',  # Most efficient solver for large datasets
            n_jobs=max(1, multiprocessing.cpu_count() // 2),  # Use half the cores
            penalty='l1',  # Sparse model
            random_state=42
        )
        
        # Fit the model
        clf.fit(X_train_scaled, y_train)
        
        # Evaluate
        logging.info("Evaluating model")
        y_pred = clf.predict(X_test_scaled)
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        
        logging.info(f"Model accuracy: {accuracy:.2f}")
        logging.info("Classification Report:\n" + report)
        
        # Save model components
        ml_model = URLThreatModel()
        ml_model.model = clf
        ml_model.save_model(model_path)
        
        # Save vectorizer and scaler
        joblib.dump(vectorizer, vectorizer_path)
        joblib.dump(scaler, os.path.join(model_dir, 'url_scaler.joblib'))
        
        logging.info(f"Model saved to {model_path}")
        logging.info(f"Vectorizer saved to {vectorizer_path}")
        return True
    
    except Exception as e:
        logging.error(f"Training error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    train_model()