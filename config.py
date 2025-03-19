import os
from dotenv import load_dotenv

load_dotenv()

class Configuration:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///threat_database.db')
    VIRUSTOTAL_API_KEY = os.getenv('1844b2e98fab279741ab85b9f7a76854455fd41c73ae8745abd5b7833c510c36', '')
    GOOGLE_SAFE_BROWSING_KEY = os.getenv('AIzaSyAGVHxisTVY8i4OpNaS9c9sNIYE1kjGKmU', '')