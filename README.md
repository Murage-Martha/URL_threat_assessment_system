# URL Threat Analysis System

A web-based system for analyzing URLs for potential security threats.

## Setup

1. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create .env file with required variables:
Get that from the owners. 

4. Train the Machine Learning model
```bash
python train_model.py
```

5. Run the application
```bash
python run.py
```