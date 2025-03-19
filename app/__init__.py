from flask import Flask


from flask_talisman import Talisman
from .database.db import init_db
from .models.ml_model import URLThreatModel
from .services.external_api import ExternalAPIService
from .services.url_analyzer import URLAnalyzer

from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from redis import Redis
import os

# Initialize with Redis storage
redis_client = Redis(host='localhost', port=6379, db=0)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

limiter = Limiter(key_func=get_remote_address)
talisman = Talisman()

def create_app(config_object):
    app = Flask(__name__)
    app.config.from_object(config_object)
    
    # Initialize security
    talisman.init_app(
        app,
        force_https=False,  # Add this line to disable HTTPS enforcement
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' 'unsafe-eval'",
            'style-src': "'self' 'unsafe-inline'",
        }
    )
    
    # Initialize rate limiter
    limiter.init_app(app)
    
    # Initialize database
    db_session = init_db(app)
    
    # Initialize services
    external_api_service = ExternalAPIService(
        virustotal_key=app.config['VIRUSTOTAL_API_KEY'],
        gsb_key=app.config['GOOGLE_SAFE_BROWSING_KEY']
    )
    
    # Load trained model (use the latest model if available)
    model_path = os.path.join(app.root_path, 'models/saved_models/latest_model.joblib')
    if not os.path.exists(model_path):
        model_path = app.config.get('ML_MODEL_PATH')
    
    ml_model = URLThreatModel(model_path=model_path)
    
    # Initialize URL analyzer
    url_analyzer = URLAnalyzer(db_session, external_api_service, ml_model)
    
    # Register blueprints
    from .routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Add url_analyzer to app context
    app.url_analyzer = url_analyzer
    
    return app
