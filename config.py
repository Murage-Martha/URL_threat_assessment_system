import os
from dotenv import load_dotenv

load_dotenv()

class Configuration:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///threat_database.db')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    GOOGLE_SAFE_BROWSING_KEY = os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')