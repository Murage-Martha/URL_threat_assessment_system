import os
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, redirect, url_for
from app.database.db import init_db
from app.models.ml_model import URLThreatModel
from app.services.external_api import ExternalAPIService
from app.services.url_analyzer import URLAnalyzer
from config import Configuration
import joblib

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__, template_folder='templates')
app.config.from_object(Configuration)  # Load configuration settings

db_session = init_db(app)  # Initialize the database session with the app instance
external_api_service = ExternalAPIService(
    virustotal_api_key=Configuration.VIRUSTOTAL_API_KEY,
    google_safe_browsing_key=Configuration.GOOGLE_SAFE_BROWSING_KEY
)

# Load the trained model, vectorizer, and scaler
model_path = os.path.join('models', 'url_threat_model.joblib')
vectorizer_path = os.path.join('models', 'url_vectorizer.joblib')
scaler_path = os.path.join('models', 'url_scaler.joblib')

ml_model = URLThreatModel()
ml_model.load_model(model_path)
vectorizer = joblib.load(vectorizer_path)
scaler = joblib.load(scaler_path)

url_analyzer = URLAnalyzer(db_session, external_api_service, ml_model)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        logging.debug(f"Request data: {data}")
        url = data.get('url') if data else None
        logging.debug(f"Received URL: {url}")
        if url:
            try:
                # Analyze the URL
                report = url_analyzer.analyze_url(url)
                explanation = None
                try:
                    # Attempt to generate an explanation using the ML model
                    explanation = ml_model.explain_prediction(url)
                except Exception as e:
                    logging.error(f"Error generating explanation with ML model: {e}")
                    # Proceed without explanation if ML model fails

                # Return the report and explanation (if available)
                return jsonify({
                    'analysis_id': report['analysis_id'],
                    'threat_status': report['threat_status'],
                    'threat_score': report['threat_score'],
                    'source': report['source'],
                    'external_api_results': report['external_api_results'],
                    'explanation': explanation
                })
            except Exception as e:
                logging.error(f"Error during URL analysis: {e}")
                # Return only external API results if ML model fails
                return jsonify({'error': 'An error occurred during URL analysis. Please try again later.'}), 500
        else:
            logging.error("No URL provided")
            return jsonify({'error': 'No URL provided'}), 400
    except Exception as e:
        logging.error(f"Error parsing request data: {e}")
        return jsonify({'error': 'Invalid request data'}), 400

@app.route('/report')
def report():
    analysis_id = request.args.get('analysis_id')
    logging.debug(f"Received analysis ID: {analysis_id}")
    if analysis_id:
        threat = url_analyzer._check_threat_database(analysis_id)
        if threat:
            report = url_analyzer._display_analysis_report(threat)
            # Ensure external_api_results is always present
            report['external_api_results'] = report.get('external_api_results', {})
            return render_template('report.html', report=report, now=datetime.now(timezone.utc))
    logging.error("Analysis ID not found or invalid")
    return redirect(url_for('index'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message="Internal server error"), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('APP_PORT', 5000)))