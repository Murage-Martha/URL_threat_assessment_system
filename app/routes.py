from flask import Blueprint, render_template, request, jsonify, current_app, Response, session, redirect, url_for
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
import validators
import os

main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# Rate limiting decorators
limiter = Limiter(key_func=get_remote_address)

# Admin credentials section
# Admin credentials (store these securely in environment variables or config)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'password')

def check_auth(username, password):
    """Check if a username/password combination is valid."""
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def authenticate():
    """Send a 401 response to prompt for basic authentication."""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )
 
#Routing to the home page
@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    # Check for URL in form data or JSON payload
    url = request.form.get('url') or (request.json and request.json.get('url'))
    
    if not url:
        if request.is_json:
            return jsonify({'error': 'No URL provided'}), 400
        return render_template('error.html', error_message='No URL provided'), 400
    
    if not validators.url(url):
        if request.is_json:
            return jsonify({'error': 'Invalid URL format'}), 400
        return render_template('error.html', error_message='Invalid URL format'), 400
    
    try:
        report = current_app.url_analyzer.analyze_url(url)
        
        # Return JSON if the request is from fetch or expects JSON
        if request.is_json or request.headers.get('Accept') == 'application/json':
            return jsonify(report)
        
        # Otherwise, render the HTML template
        return render_template('report.html', report=report)
    except Exception as e:
        if request.is_json:
            return jsonify({'error': str(e)}), 500
        return render_template('error.html', error_message=str(e)), 500

# Routing to the admin page
@main_bp.route('/admin')
def admin_panel():
    if not session.get('logged_in'):  # Check if the user is logged in
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()  # Prompt for credentials if not authenticated

        # Set session variable to indicate the user is logged in
        session['logged_in'] = True

    return render_template('admin.html')  # Render the admin panel if authenticated

@main_bp.route('/logout')
def logout():
    """Log out the user by clearing the session and forcing re-authentication."""
    session.clear()  # Clear the session
    return Response(
        'Logged out successfully.', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


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
