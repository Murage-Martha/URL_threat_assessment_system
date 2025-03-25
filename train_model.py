import os
import pandas as pd
from dotenv import load_dotenv
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier
from app.models.ml_model import URLThreatModel
from scipy.stats import randint

def train_model():
    load_dotenv()
    
    print("Starting URL threat model training")
    
    # Set up paths
    data_file = os.getenv('DATASET_PATH', 'malicious_phish.csv')
    model_dir = 'models'
    model_path = os.path.join(model_dir, 'url_threat_model.joblib')
    
    # Create model directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    # Load dataset
    print(f"Loading dataset from {data_file}")
    try:
        df = pd.read_csv(data_file)
        print(f"Dataset loaded successfully with {len(df)} entries")
        
        # Process dataset
        urls = df['url']
        # Handle different label formats (dataset might use 'benign'/'malicious' or other formats)
        labels = []
        for label in df['label'].tolist():
            if isinstance(label, str):
                label_lower = label.lower()
                if label_lower == 'benign' or label_lower == 'safe':
                    labels.append(0)
                else:  # 'malicious', 'phishing', etc.
                    labels.append(1)
            else:
                # Assuming numeric labels where 0 is safe and anything else is not
                labels.append(1 if label != 0 else 0)
        
        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(urls, labels, test_size=0.2, random_state=42)
        
        # Initialize model
        ml_model = URLThreatModel()
        
        # Fit the feature extractor on the training data
        ml_model.feature_extractor.fit(X_train)
        
        # Transform the URLs into numerical features
        X_train_transformed = ml_model.feature_extractor.transform(X_train)
        X_test_transformed = ml_model.feature_extractor.transform(X_test)
        
        # Use a smaller subset for hyperparameter tuning
        X_train_subset, _, y_train_subset, _ = train_test_split(X_train_transformed, y_train, test_size=0.9, random_state=42)
        
        # Hyperparameter tuning with randomized search
        print(f"Hyperparameter tuning with {X_train_subset.shape[0]} URLs")
        param_dist = {
            'n_estimators': randint(100, 150),
            'max_depth': [10, 20],
            'min_samples_split': randint(2, 4),
            'min_samples_leaf': randint(1, 2)
        }
        random_search = RandomizedSearchCV(RandomForestClassifier(), param_distributions=param_dist, n_iter=10, cv=3, n_jobs=-1, verbose=2, random_state=42)
        random_search.fit(X_train_subset, y_train_subset)
        
        # Train final model on full dataset with best hyperparameters
        print(f"Training final model with {X_train_transformed.shape[0]} URLs")
        best_params = random_search.best_params_
        final_model = RandomForestClassifier(**best_params)
        ml_model.train(X_train, y_train, final_model)
        
        # Test model
        print(f"Testing model with {X_test_transformed.shape[0]} URLs")
        y_pred = ml_model.predict(X_test)
        
        # Evaluate model
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        
        print(f"Model accuracy: {accuracy:.2f}")
        print("Classification Report:")
        print(report)
        
        # Save model
        ml_model.save_model(model_path)
        print(f"Model saved successfully to {model_path}")
        
        return True
    except Exception as e:
        print(f"Error training model: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    train_model()