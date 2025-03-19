from flask import Blueprint, render_template, request, jsonify, current_app
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
import validators

main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# Rate limiting decorators
limiter = Limiter(key_func=get_remote_address)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    url = request.form.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    try:
        report = current_app.url_analyzer.analyze_url(url)
        return render_template('report.html', report=report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/analyze', methods=['POST'])
@limiter.limit("60 per hour")
def api_analyze():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
    
    url = data['url']
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    try:
        report = current_app.url_analyzer.analyze_url(url)
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
