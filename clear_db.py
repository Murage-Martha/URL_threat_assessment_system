from flask import Flask
from app.database.db import init_db, URLThreat
from config import Configuration

def clear_threat_database():
    app = Flask(__name__)
    app.config.from_object(Configuration)
    db_session = init_db(app)
    
    with app.app_context():
        db_session.query(URLThreat).delete()
        db_session.commit()
        print("Threat database cleared.")

if __name__ == "__main__":
    clear_threat_database()