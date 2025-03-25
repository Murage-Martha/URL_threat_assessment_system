import os
import logging
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, redirect, url_for
from app.database.db import init_db
from app.models.ml_model import URLThreatModel
from app.services.external_api import ExternalAPIService
from app.services.url_analyzer import URLAnalyzer
from config import Configuration

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__, template_folder='templates')
app.config.from_object(Configuration)  # Load configuration settings

db_session = init_db(app)  # Initialize the database session with the app instance
external_api_service = ExternalAPIService(
    virustotal_api_key=Configuration.VIRUSTOTAL_API_KEY,
    google_safe_browsing_key=Configuration.GOOGLE_SAFE_BROWSING_KEY
)
ml_model = URLThreatModel()

# Load the trained model
model_path = os.path.join('models', 'url_threat_model.joblib')
if os.path.exists(model_path):
    ml_model.load_model(model_path)
    logging.info(f"Model loaded successfully from {model_path}")
else:
    logging.error(f"Model file not found at {model_path}. Please train the model first.")

url_analyzer = URLAnalyzer(db_session, external_api_service, ml_model)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get('url')
    logging.debug(f"Received URL: {url}")
    if url:
        try:
            # Analyze the URL
            report = url_analyzer.analyze_url(url)
            return jsonify({'analysis_id': report['details']['analysis_id']})
        except Exception as e:
            logging.error(f"Error during URL analysis: {e}")
            return jsonify({'error': 'An error occurred during URL analysis. Please try again later.'}), 500
    else:
        logging.error("No URL provided")
        return jsonify({'error': 'No URL provided'}), 400

@app.route('/report')
def report():
    analysis_id = request.args.get('analysis_id')
    logging.debug(f"Received analysis ID: {analysis_id}")
    if analysis_id:
        threat = url_analyzer._check_threat_database(analysis_id)
        if threat:
            report = url_analyzer._display_analysis_report(threat)
            return render_template('report.html', report=report)
    logging.error("Analysis ID not found or invalid")
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message="Internal server error"), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('APP_PORT', 5000)))