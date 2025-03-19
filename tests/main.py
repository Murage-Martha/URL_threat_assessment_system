import os
from dotenv import load_dotenv
from app.database.db import init_db, URLThreat
from app.services.external_api import ExternalAPIService
from config import Configuration

load_dotenv()

def test_configuration():
    print("\n=== Testing Configuration ===")
    required_vars = ['SECRET_KEY', 'DATABASE_URL', 'VIRUSTOTAL_API_KEY', 'GOOGLE_SAFE_BROWSING_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
        return False
    print("✅ All configuration variables present")
    return True

def test_database():
    print("\n=== Testing Database ===")
    from flask import Flask
    app = Flask(__name__)
    app.config.from_object(Configuration)
    db_session = init_db(app)

    test_url = URLThreat(
        url="https://example.com",
        threat_status="safe",
        threat_score=0.1,
        source="test"
    )
    db_session.add(test_url)
    db_session.commit()

    result = db_session.query(URLThreat).filter_by(url="https://example.com").first()
    if result:
        print("✅ Database operations successful")
        db_session.delete(result)
        db_session.commit()
        return True
    return False

def test_external_apis():
    print("\n=== Testing External APIs ===")
    api_service = ExternalAPIService(
        virustotal_key=os.getenv('VIRUSTOTAL_API_KEY'),
        gsb_key=os.getenv('GOOGLE_SAFE_BROWSING_KEY')
    )
    
    test_urls = ["https://www.google.com"]
    
    for url in test_urls:
        vt_result = api_service.check_virustotal(url)
        print(f"✅ VirusTotal API Response: {vt_result}")

        gsb_result = api_service.check_google_safe_browsing(url)
        print(f"✅ Google Safe Browsing API Response: {gsb_result}")

if __name__ == "__main__":
    test_configuration()
    test_database()
    test_external_apis()
