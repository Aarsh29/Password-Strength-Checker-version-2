import hashlib
from flask import Flask, render_template, request, jsonify
from database import init_db, is_password_used, add_password_hash
from utils import analyze_password, generate_random_password

app = Flask(__name__)

# Initialize database schema and unique indexes on startup
init_db()

@app.route('/')
def index():
    """
    Serve the main user interface.
    """
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Perform a read-only security audit on the password.
    Queries the database using O(1) fingerprint lookups and checks the HIBP API.
    Does NOT save the password hash.
    """
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({
            'error': 'Password cannot be empty.'
        }), 400
        
    # Check if this password was previously committed to history
    is_used = is_password_used(password)
    
    # Run audit logic
    report = analyze_password(password, is_previously_used=is_used)
    
    # Generate standard SHA-256 hex digest for visual representation in frontend
    report['sha256_hash'] = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    return jsonify(report)

@app.route('/save', methods=['POST'])
def save_password():
    """
    Explicitly commit the password hash to the local SQLite history vault.
    
    Converts password to:
    1. A peppered SHA-256 fingerprint for O(1) quick-lookup.
    2. A salted bcrypt hash for secure offline storage.
    """
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({
            'error': 'Password cannot be empty.'
        }), 400
        
    # Commits to database history
    newly_added = add_password_hash(password)
    
    if newly_added:
        return jsonify({
            'success': True,
            'message': 'Password fingerprint committed to secure database vault!'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'This password fingerprint is already registered in your vault.'
        })

@app.route('/generate', methods=['GET'])
def generate():
    """
    Generate a random, cryptographically secure strong password.
    Supports a custom length parameter (default is 16).
    """
    try:
        length = int(request.args.get('length', 16))
    except ValueError:
        length = 16
        
    length = max(8, min(64, length))
    
    strong_pwd = generate_random_password(length)
    return jsonify({
        'password': strong_pwd
    })

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
