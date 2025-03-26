import os
import re
import pandas as pd
import numpy as np
from dotenv import load_dotenv
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from app.models.ml_model import URLThreatModel
from scipy.stats import randint
from scipy.sparse import hstack
import logging

def extract_features(urls):
    features = pd.DataFrame()
    features['url_length'] = urls.apply(len)
    features['num_special_chars'] = urls.apply(lambda x: len(re.findall(r'[-_@?%/]', x)))
    features['has_ip'] = urls.apply(lambda x: int(bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', x))))
    features['has_https'] = urls.apply(lambda x: int(x.startswith('https')))
    features['domain_length'] = urls.apply(lambda x: len(re.findall(r'://([^/]+)/?', x)[0]) if re.findall(r'://([^/]+)/?', x) else 0)
    features['num_subdomains'] = urls.apply(lambda x: len(re.findall(r'\.', re.findall(r'://([^/]+)/?', x)[0])) if re.findall(r'://([^/]+)/?', x) else 0)
    features['num_sensitive_words'] = urls.apply(lambda x: len(re.findall(r'login|bank|secure', x)))
    features['num_numeric_chars'] = urls.apply(lambda x: len(re.findall(r'\d', x)))
    return features

def train_model():
    load_dotenv()
    logging.basicConfig(level=logging.DEBUG)
    
    logging.info("Starting URL threat model training")
    
    # Set up paths
    data_file = os.getenv('DATASET_PATH', 'malicious_phish.csv')
    model_dir = 'models'
    model_path = os.path.join(model_dir, 'url_threat_model.joblib')
    
    # Create model directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    # Load dataset
    logging.info(f"Loading dataset from {data_file}")
    try:
        df = pd.read_csv(data_file)
        logging.info(f"Dataset loaded successfully with {len(df)} entries")
        
        # Process dataset
        urls = df['url']
        labels = df['label'].apply(lambda x: 0 if x.lower() in ['benign', 'safe'] else 1)
        
        # Extract features
        logging.info("Extracting features from URLs")
        lexical_features = extract_features(urls)
        
        # Vectorize URLs using TF-IDF
        logging.info("Vectorizing URLs using TF-IDF")
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5))
        tfidf_features = vectorizer.fit_transform(urls)
        
        # Combine features using sparse matrices
        logging.info("Combining lexical and TF-IDF features")
        combined_features = hstack([lexical_features, tfidf_features])
        
        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(combined_features, labels, test_size=0.2, random_state=42)
        
        # Initialize model
        ml_model = URLThreatModel()
        
        # Hyperparameter tuning with randomized search
        logging.info(f"Hyperparameter tuning with {X_train.shape[0]} URLs")
        param_dist = {
            'n_estimators': randint(100, 150),
            'max_depth': [10, 20],
            'min_samples_split': randint(2, 4),
            'min_samples_leaf': randint(1, 2)
        }
        random_search = RandomizedSearchCV(RandomForestClassifier(), param_distributions=param_dist, n_iter=10, cv=3, n_jobs=-1, verbose=2, random_state=42)
        random_search.fit(X_train, y_train)
        
        # Train final model on full dataset with best hyperparameters
        logging.info(f"Training final model with {X_train.shape[0]} URLs")
        best_params = random_search.best_params_
        final_model = RandomForestClassifier(**best_params)
        ml_model.train(X_train, y_train, final_model)
        
        # Test model
        logging.info(f"Testing model with {X_test.shape[0]} URLs")
        y_pred = ml_model.predict(X_test)
        
        # Evaluate model
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        logging.info(f"Model accuracy: {accuracy:.2f}")
        logging.info("Classification Report:")
        logging.info(report)
        logging.info("Confusion Matrix:")
        logging.info(conf_matrix)
        
        # Save model
        ml_model.save_model(model_path)
        logging.info(f"Model saved successfully to {model_path}")
        
        return True
    except Exception as e:
        logging.error(f"Error training model: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    train_model()