from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class URLThreat(Base):
    __tablename__ = 'url_threats'
    
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False, index=True)
    analysis_id = Column(String, unique=True, nullable=False)
    threat_status = Column(String, nullable=False)  # safe, suspicious, malicious
    threat_score = Column(Float)
    source = Column(String)  # database, external_api, ml_model
    created_at = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, default=datetime.utcnow)
    external_api_results = Column(String)  # Store JSON string of API results
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_checked = datetime.utcnow()
    
    def to_dict(self):
        return {
            'url': self.url,
            'threat_status': self.threat_status,
            'threat_score': self.threat_score,
            'source': self.source,
            'created_at': self.created_at.isoformat()
        }

def init_db(app):
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()
