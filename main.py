import re
from bson import ObjectId
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, make_response, flash
from authlib.integrations.flask_client import OAuth
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timedelta
import urllib
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import json
from flask_cors import CORS
from urllib.parse import urlencode
import requests
import secrets
import uuid
import hashlib
from collections import OrderedDict
from urllib.parse import parse_qsl
from Utils.EmailSender import send_password_reset_email

# Load environment variables
load_dotenv()

# Configuration
API_URL = os.getenv('API_URL')
API_KEY = os.getenv('API_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Default for development
MONGO_URI = os.getenv('MONGO_URI')
MODE = os.getenv('MODE', 'development')

# PayFast Configuration
PAYFAST_MERCHANT_ID = os.getenv('PAYFAST_MERCHANT_ID')
PAYFAST_MERCHANT_KEY = os.getenv('PAYFAST_MERCHANT_KEY')
PAYFAST_PASSPHRASE = os.getenv('PAYFAST_PASSPHRASE', '')
PAYFAST_SANDBOX = os.getenv('PAYFAST_SANDBOX', 'true').lower() == 'true'

app = Flask(__name__, static_folder='static')
CORS(app)
app.logger.warning(f"PAYFAST_PASSPHRASE: '{PAYFAST_PASSPHRASE}'")

app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = MODE == 'production'  # True in production

app.logger.setLevel(logging.INFO)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# MongoDB Setup
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client["geotech_db"]
users_collection = db["users"]
dashboard_stats_collection = db["dashboard_stats"]
feedback_collection = db["feedback"]  # Add new collection for feedback
sessions_collection = db["sessions"]  # New collection for session management
password_reset_collection = db["password_reset_tokens"]  # New collection for password reset tokens

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }
)

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USERNAME)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

app.json_encoder = JSONEncoder

# Session management functions
def generate_session_token():
    """Generate a unique session token"""
    return str(uuid.uuid4())

def create_user_session(user_email, session_id=None):
    """Create a new session for a user"""
    if session_id is None:
        session_id = generate_session_token()
    
    # Remove any existing sessions for this user
    sessions_collection.delete_many({"user_email": user_email})
    
    # Create new session
    session_data = {
        "session_id": session_id,
        "user_email": user_email,
        "created_at": datetime.utcnow(),
        "last_activity": datetime.utcnow(),
        "user_agent": request.headers.get('User-Agent', ''),
        "ip_address": request.remote_addr
    }
    
    sessions_collection.insert_one(session_data)
    return session_id

def validate_session(session_id, user_email):
    """Validate if a session is still active"""
    session_data = sessions_collection.find_one({
        "session_id": session_id,
        "user_email": user_email
    })
    
    if not session_data:
        return False
    
    # Check if session is expired (24 hours)
    if datetime.utcnow() - session_data["created_at"] > timedelta(hours=24):
        sessions_collection.delete_one({"_id": session_data["_id"]})
        return False
    
    # Update last activity
    sessions_collection.update_one(
        {"_id": session_data["_id"]},
        {"$set": {"last_activity": datetime.utcnow()}}
    )
    
    return True

def remove_user_session(user_email):
    """Remove all sessions for a user"""
    sessions_collection.delete_many({"user_email": user_email})

def get_active_session_info(user_email):
    """Get information about the active session for a user"""
    app.logger.info(f"Getting active session info for user: {user_email}")
    session_data = sessions_collection.find_one({"user_email": user_email})
    app.logger.info(f"Session data found: {session_data is not None}")
    
    if session_data:
        # Check if session is expired
        if datetime.utcnow() - session_data["created_at"] > timedelta(hours=24):
            app.logger.info(f"Session expired for user: {user_email}")
            sessions_collection.delete_one({"_id": session_data["_id"]})
            return None
            
        app.logger.info(f"Active session found for user: {user_email}")
        return {
            "session_id": session_data["session_id"],
            "created_at": session_data["created_at"],
            "last_activity": session_data["last_activity"],
            "user_agent": session_data["user_agent"],
            "ip_address": session_data["ip_address"]
        }
    
    app.logger.info(f"No active session found for user: {user_email}")
    return None

# Login decorator with session validation
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        
        # Validate session
        user_email = session['user'].get('email')
        session_id = session.get('session_id')
        
        if not user_email or not session_id:
            session.clear()
            return redirect(url_for('login'))
        
        if not validate_session(session_id, user_email):
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

# Initialize user dashboard stats
def initialize_new_user_dashboard_stats(email):
    stats = {
        "user_email": email,
        "total_chats": 0,
        "total_messages": 0,
        "last_active": datetime.utcnow(),
        "created_at": datetime.utcnow()
    }
    dashboard_stats_collection.insert_one(stats)
    return stats

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Password Reset Token Management
def generate_reset_token():
    """Generate a secure random token for password reset"""
    return secrets.token_urlsafe(32)

def create_password_reset_token(email):
    """Create a password reset token for a user"""
    try:
        # Remove any existing tokens for this email
        password_reset_collection.delete_many({"email": email})
        
        # Generate new token
        token = generate_reset_token()
        
        # Create token record (expires in 1 hour)
        token_data = {
            "email": email,
            "token": token,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "used": False
        }
        
        password_reset_collection.insert_one(token_data)
        return token
        
    except Exception as e:
        app.logger.error(f"Error creating password reset token: {str(e)}")
        return None

def validate_reset_token(token):
    """Validate a password reset token"""
    try:
        token_data = password_reset_collection.find_one({
            "token": token,
            "used": False,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        return token_data
        
    except Exception as e:
        app.logger.error(f"Error validating reset token: {str(e)}")
        return None

def mark_token_as_used(token):
    """Mark a password reset token as used"""
    try:
        password_reset_collection.update_one(
            {"token": token},
            {"$set": {"used": True, "used_at": datetime.utcnow()}}
        )
        return True
    except Exception as e:
        app.logger.error(f"Error marking token as used: {str(e)}")
        return False

def cleanup_expired_reset_tokens():
    """Clean up expired password reset tokens"""
    try:
        result = password_reset_collection.delete_many({
            "expires_at": {"$lt": datetime.utcnow()}
        })
        app.logger.info(f"Cleaned up {result.deleted_count} expired reset tokens")
    except Exception as e:
        app.logger.error(f"Error cleaning up expired reset tokens: {str(e)}")

PAYFAST_PASSPHRASE = 'xsdfgscdsdsa'
IS_SANDBOX = True


def generate_payfast_signature(data, passphrase=''):
    # Step 1: Remove 'signature' and empty or 'no value' fields
    filtered_data = {
        k: v for k, v in data.items()
        if k != 'signature' and str(v).strip().lower() != 'no value' and str(v).strip() != ''
    }

    # Step 2: Sort alphabetically by keys
    sorted_items = sorted(filtered_data.items())

    # Step 3: Concatenate with raw values (no quote_plus)
    payload = "&".join([f"{k}={str(v)}" for k, v in sorted_items])

    # Step 4: Add passphrase if present
    if passphrase:
        payload += f"&passphrase={passphrase}"

    # Step 5: Return MD5 hash
    return hashlib.md5(payload.encode('utf-8')).hexdigest()


def verify_payfast_itn(data):
    try:
        received_signature = data.get('signature')
        passphrase = PAYFAST_PASSPHRASE if IS_SANDBOX else ''


        calculated_signature = generate_payfast_signature(data, passphrase)

        if received_signature != calculated_signature:
            app.logger.warning(f"Signature mismatch:\nReceived: {received_signature}\nExpected: {calculated_signature}")
            return False

        return True
    except Exception as e:
        app.logger.error(f"Error verifying PayFast ITN: {str(e)}")
        return False

def cleanup_expired_sessions():
    """Clean up expired sessions (older than 24 hours)"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        result = sessions_collection.delete_many({
            "created_at": {"$lt": cutoff_time}
        })
        app.logger.info(f"Cleaned up {result.deleted_count} expired sessions")
        
        # Also cleanup expired reset tokens
        cleanup_expired_reset_tokens()
        
    except Exception as e:
        app.logger.error(f"Error cleaning up expired sessions: {str(e)}")

# Schedule cleanup task (run every hour)
def schedule_cleanup():
    """Schedule the cleanup task to run periodically"""
    import threading
    import time
    
    def cleanup_worker():
        while True:
            try:
                cleanup_expired_sessions()
                time.sleep(3600)  # Run every hour
            except Exception as e:
                app.logger.error(f"Error in cleanup worker: {str(e)}")
                time.sleep(3600)  # Continue trying every hour
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

# Start cleanup scheduler
schedule_cleanup()

# --- Hardcoded upload page users ---
UPLOAD_USERS = [
    {
        'email': 'david@intailings.com',
        'password_hash': generate_password_hash('1234david'),
        'name': 'User One',
    },
    {
        'email': 'finely@intailings.com',
        'password_hash': generate_password_hash('1234david'),
        'name': 'User Two',
    },
]

@app.route('/upload-login', methods=['POST'])
def upload_login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # Only allow the two hardcoded users
    user = next((u for u in UPLOAD_USERS if u['email'] == email), None)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 401
    
    # Set session for upload page
    session.permanent = True
    session['user'] = {
        'email': user['email'],
        'name': user['name'],
        'auth_method': 'upload_modal',
    }
    session['upload_access'] = True
    return jsonify({'success': True, 'user': session['user']})

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detail')
def detail():
    return render_template('detail.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')




# --- Modified Signup Endpoint ---
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        if not is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'}), 400

        # Check if user already exists
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return jsonify({'success': False, 'error': 'An account with this email already exists'}), 400

        # Hash password and create user (verified immediately since no OTP flow)
        hashed_password = generate_password_hash(password)
        user_data = {
            'email': email,
            'password': hashed_password,
            'name': email.split('@')[0].title(),
            'picture': '/static/default-profile.png',
            'auth_method': 'email',
            'created_at': datetime.utcnow(),
            'last_login': datetime.utcnow(),
            'verified': True
        }
        users_collection.insert_one(user_data)
        initialize_new_user_dashboard_stats(email)

        return jsonify({'success': True, 'message': 'Account created successfully! You can now sign in.'})

    except Exception as e:
        app.logger.error(f"Error in signup: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during registration'}), 500



@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # Find user
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Check if user signed up with email/password (not Google)
        if user.get('auth_method') != 'email':
            return jsonify({'success': False, 'error': 'Please sign in with Google'}), 401

        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Check if user already has an active session
        app.logger.info(f"Checking for active session for user: {email}")
        active_session = get_active_session_info(email)
        app.logger.info(f"Active session found: {active_session is not None}")
        
        if active_session:
            app.logger.info(f"Session conflict detected for user: {email}")
            # Return session conflict information
            return jsonify({
                'success': False, 
                'error': 'session_conflict',
                'message': 'This account is already active on another device. Do you want to continue and log out the other session?',
                'session_info': {
                    'user_agent': active_session['user_agent'],
                    'ip_address': active_session['ip_address'],
                    'last_activity': active_session['last_activity'].isoformat()
                }
            }), 409
        
        # Update last login
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        # Create new session
        session_id = create_user_session(email)

        # Set session, include premium status if present
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user['name'],
            'picture': user['picture'],
            'auth_method': user['auth_method'],
            'premium': user.get('premium', False)
        }
        session['session_id'] = session_id

        app.logger.info(f"User signed in: {email}")
        return jsonify({
            'success': True,
            'user': session['user']
        })

    except Exception as e:
        app.logger.error(f"Error in signin: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during sign in'}), 500


# Password Reset Endpoints
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        # Validation
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        if not is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        # Check if user exists and uses email authentication
        user = users_collection.find_one({'email': email})
        if not user:
            # Don't reveal if user exists or not for security
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        
        # Only allow password reset for email-authenticated users
        if user.get('auth_method') != 'email':
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        
        # Generate reset token
        reset_token = create_password_reset_token(email)
        if not reset_token:
            return jsonify({'success': False, 'error': 'Failed to generate reset token'}), 500
        
        # Create reset link
        reset_link = url_for('reset_password_page', token=reset_token, _external=True)
        
        # Send email using the new EmailSender package
        error_message = send_password_reset_email(email, reset_link)
        
        if error_message is None:
            app.logger.info(f"Password reset email sent to: {email}")
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        else:
            app.logger.error(f"Failed to send password reset email to: {email}. Reason: {error_message}")
            return jsonify({'success': False, 'error': 'Failed to send reset email'}), 500
        
    except Exception as e:
        app.logger.error(f"Error in forgot_password: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while processing your request'}), 500


@app.route('/reset-password/<token>')
def reset_password_page(token):
    """Display password reset form"""
    # Validate token
    token_data = validate_reset_token(token)
    if not token_data:
        return render_template('reset_password.html', error="Invalid or expired reset link")
    
    return render_template('reset_password.html', token=token, email=token_data['email'])


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('password', '')
        
        # Validation
        if not token or not new_password:
            return jsonify({'success': False, 'error': 'Token and password are required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'}), 400
        
        # Validate token
        token_data = validate_reset_token(token)
        if not token_data:
            return jsonify({'success': False, 'error': 'Invalid or expired reset token'}), 400
        
        # Get user
        user = users_collection.find_one({'email': token_data['email']})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Update password
        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password, 'last_login': datetime.utcnow()}}
        )
        
        # Mark token as used
        mark_token_as_used(token)
        
        # Remove all active sessions for this user (force re-login)
        remove_user_session(token_data['email'])
        
        app.logger.info(f"Password reset successful for: {token_data['email']}")
        return jsonify({'success': True, 'message': 'Password reset successful! You can now sign in with your new password.'})
        
    except Exception as e:
        app.logger.error(f"Error in reset_password: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while resetting your password'}), 500


@app.route('/login')
def login():
    session.clear()
    session['oauth_state'] = os.urandom(16).hex()
    session.modified = True
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(
        redirect_uri=redirect_uri,
        state=session['oauth_state']
    )

@app.route('/google/callback')
def google_callback():
    try:
        state = request.args.get('state')
        stored_state = session.get('oauth_state')

        if not state or not stored_state or state != stored_state:
            raise ValueError("State verification failed")
        
        session.pop('oauth_state', None)

        token = google.authorize_access_token()
        if not token:
            raise ValueError("Failed to get access token")

        # Get user info from Google
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
        user_info = resp.json()
        
        if not user_info or 'email' not in user_info:
            raise ValueError("Failed to get user info")

        # Check if user already has an active session
        active_session = get_active_session_info(user_info["email"])
        if active_session:
            # Store session conflict info in session for later handling
            session['session_conflict'] = {
                'user_email': user_info["email"],
                'session_info': {
                    'user_agent': active_session['user_agent'],
                    'ip_address': active_session['ip_address'],
                    'last_activity': active_session['last_activity'].isoformat()
                }
            }
            return redirect(url_for('session_conflict'))

        # Store user data in MongoDB
        user_data = {
            "name": user_info.get("name", "User"),
            "email": user_info["email"],
            "picture": user_info.get("picture", "/static/default-profile.png"),
            "last_login": datetime.utcnow(),
            "auth_method": "google"  # Add auth method
        }

        # Update user or create if doesn't exist
        result = users_collection.update_one(
            {"email": user_data["email"]},
            {"$set": user_data},
            upsert=True
        )

        # Initialize dashboard stats for new users
        if result.upserted_id:
            initialize_new_user_dashboard_stats(user_data["email"])

        # Fetch the full user record (including premium status)
        db_user = users_collection.find_one({"email": user_data["email"]})

        # Create new session
        session_id = create_user_session(user_data["email"])

        # Set session, include premium status if present
        session.permanent = True
        session['user'] = {
            'email': db_user['email'],
            'name': db_user['name'],
            'picture': db_user['picture'],
            'auth_method': db_user['auth_method'],
            'premium': db_user.get('premium', False)
        }
        session['session_id'] = session_id
        session.modified = True

        app.logger.info(f"Google login successful for user: {user_data['email']}")
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error in Google callback: {str(e)}")
        session.clear()
        return redirect(url_for('index'))

@app.route('/check-login-status')
def check_login_status():
    user = session.get('user')
    if user:
        return jsonify({'loggedIn': True})
    return jsonify({'loggedIn': False})

@app.route('/api/user-profile')
def user_profile():
    user = session.get('user')
    if not user:
        return jsonify({"error": "Not logged in"}), 401

    # Fetch the full user document from MongoDB
    db_user = users_collection.find_one({'email': user['email']})
    if not db_user:
        return jsonify({"error": "User not found"}), 404

    # Remove sensitive fields if needed
    db_user.pop('password', None)
    db_user['_id'] = str(db_user['_id'])

    # Add the real usage count to the user dict (if you use this)
    user_limits = db.user_limits.find_one({"user_id": user["email"]})
    usage_count = user_limits["sonnet_usage_count"] if user_limits and "sonnet_usage_count" in user_limits else 0
    db_user["sonnet_usage_count"] = usage_count

    # Always include subscription info for frontend
    db_user["payfast_subscription_id"] = db_user.get("payfast_subscription_id", None)
    db_user["subscription_status"] = "active" if db_user.get("payfast_subscription_id") else "none"
    db_user["subscription_plan"] = db_user.get("subscription_plan", None)
    db_user["premium"] = db_user.get("premium", False)

    return jsonify(db_user)

@app.route('/check-upload-access')
def check_upload_access():
    if session.get('upload_access'):
        return jsonify({'uploadAccess': True})
    return jsonify({'uploadAccess': False})

@app.route('/logout', methods=['POST'])
def logout():
    user_email = session.get('user', {}).get('email')
    if user_email:
        remove_user_session(user_email)
    session.pop('upload_access', None)
    session.clear()
    return jsonify({"success": True})

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/chat_water')
@login_required
def chat_water():
    return render_template('chat_water.html')

@app.route('/chat_concrete')
@login_required
def chat_concrete():
    return render_template('chat_concrete.html')

@app.route('/chat_electrical')
@login_required
def chat_electrical():
    return render_template('chat_electrical.html')

@app.route('/chat_mining')
@login_required
def chat_mining():
    return render_template('chat_mining.html')

@app.route('/upload')
@login_required
def upload():
    return render_template('upload.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/feedback', methods=['POST', 'OPTIONS'])
@login_required
def submit_feedback():
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response

    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        user = session.get('user')
        if not user:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        feedback_data = {
            "message_id": data.get('message_id'),
            "content": data.get('content'),
            "query" :data.get('query', '').strip(),  # Add query field with empty string as default
            "is_positive": data.get('is_positive'),
            "user_email": user.get('email'),
            "timestamp": datetime.utcnow(),
            "user_agent": request.headers.get('User-Agent')
        }
        
        # Validate required fields
        if not all(key in feedback_data for key in ['message_id', 'content', 'is_positive', 'query']):
            return jsonify({"success": False, "error": "Missing required fields"}), 400
        
        # Insert feedback into MongoDB
        feedback_collection.insert_one(feedback_data)
        
        # Update dashboard stats
        dashboard_stats_collection.update_one(
            {"user_email": user.get('email')},
            {
                "$inc": {"total_feedback": 1},
                "$set": {"last_active": datetime.utcnow()}
            }
        )
        
        return jsonify({"success": True, "message": "Feedback submitted successfully"})
        
    except Exception as e:
        app.logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/invalidate-session', methods=['POST'])
def invalidate_session():
    """Invalidate current session (called when user logs in from another device)"""
    try:
        user_email = session.get('user', {}).get('email')
        if user_email:
            # Remove the current session
            remove_user_session(user_email)
        
        # Clear the session
        session.clear()
        
        return jsonify({'success': True, 'message': 'Session invalidated'})
        
    except Exception as e:
        app.logger.error(f"Error invalidating session: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to invalidate session'}), 500

@app.route('/session-conflict')
def session_conflict():
    """Handle session conflicts by showing a page to the user"""
    conflict_info = session.get('session_conflict')
    if not conflict_info:
        return redirect(url_for('index'))
    
    return render_template('session_conflict.html', conflict_info=conflict_info)

@app.route('/api/force-login', methods=['POST'])
def force_login():
    """Force login by logging out the previous session"""
    try:
        app.logger.info("Force login endpoint called")
        data = request.get_json()
        user_email = data.get('email')
        
        app.logger.info(f"Force login request for email: {user_email}")
        
        if not user_email:
            app.logger.error("Force login failed: Email is required")
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # Remove existing session
        app.logger.info(f"Removing existing sessions for user: {user_email}")
        remove_user_session(user_email)
        
        # Get user data
        user = users_collection.find_one({'email': user_email})
        if not user:
            app.logger.error(f"Force login failed: User not found for email: {user_email}")
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        app.logger.info(f"User found: {user.get('name', 'Unknown')}")
        
        # Create new session
        app.logger.info("Creating new session")
        session_id = create_user_session(user_email)
        
        # Set session
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user['name'],
            'picture': user['picture'],
            'auth_method': user['auth_method'],
            'premium': user.get('premium', False)
        }
        session['session_id'] = session_id
        
        # Clear session conflict info
        session.pop('session_conflict', None)
        
        app.logger.info(f"Force login successful for user: {user_email}")
        return jsonify({
            'success': True,
            'user': session['user']
        })
        
    except Exception as e:
        app.logger.error(f"Error in force login: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during force login'}), 500

# Serve the home page HTML file
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# For development - serve our single HTML file
@app.route('/index.html')
def serve_html():
    return render_template('index.html')

@app.route('/pay')
@login_required
def pay():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    plan = request.args.get('plan', 'monthly')
    amount = request.args.get('amount', '149.00')
    recurring = request.args.get('recurring', 'false') == 'true'

    if plan == 'annual':
        item_name = 'Premium Plan - Annual Subscription'
        recurring_amount = '1548.00'
        frequency = 6  # 6 = yearly in PayFast
    else:
        item_name = 'Premium Plan - Monthly Subscription'
        recurring_amount = '149.00'
        frequency = 3  # 3 = monthly in PayFast

    # Generate unique merchant reference for better tracking
    merchant_ref = f"{user.get('email', '')}-{plan}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    payfast_data = {
            'merchant_id': '25296103',
        'merchant_key': 'rbn0vhdzshrbi',
        'amount': amount,
        'item_name': item_name,
        'name_first': user.get('name', ''),
        'email_address': user.get('email', ''),
        'return_url': url_for('pay_success', _external=True),
        'cancel_url': url_for('pay_cancel', _external=True),
        'notify_url': url_for('pay_notify', _external=True),
        'custom_str1': user.get('email', ''),
        'custom_str2': plan,
        'custom_str3': merchant_ref,
        'm_payment_id': merchant_ref
    }

    if recurring:
        billing_date = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d')
        payfast_data.update({
            'subscription_type': 1,
            'billing_date': billing_date,
            'recurring_amount': recurring_amount,
            'frequency': frequency,
            'cycles': 0
        })
        
        app.logger.info(f"Creating recurring subscription for {user.get('email', '')}: {payfast_data}")
        print(f"Recurring subscription data: {payfast_data}")  # Terminal log

    return render_template('payfast_form.html', payfast=payfast_data, recurring=recurring)

@app.route('/pay/success')
@login_required
def pay_success():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    
    # Get plan from query parameters (in case it was passed back from PayFast)
    plan = request.args.get('plan', 'monthly')
    
    # Calculate subscription end date
    if plan == 'annual':
        subscription_end = datetime.utcnow() + timedelta(days=365)
        plan_display = "annual"
    else:
        subscription_end = datetime.utcnow() + timedelta(days=30)
        plan_display = "monthly"
    
    # Mark user as premium in DB with subscription details
    users_collection.update_one(
        {'email': user['email']}, 
        {'$set': {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.utcnow(),
            'subscription_end': subscription_end
        }}
    )
    
    # Update session
    session['user']['premium'] = True
    session['user']['subscription_plan'] = plan
    
    # Show appropriate success message
    if plan == 'annual':
        flash('Payment successful! You are now a premium user with an annual subscription.', 'success')
    else:
        flash('Payment successful! You are now a premium user with a monthly subscription.', 'success')
    
    return redirect(url_for('chat'))

@app.route('/pay/cancel')
@login_required
def pay_cancel():
    flash('Payment cancelled.', 'warning')
    return redirect(url_for('chat'))

@app.route('/pay/notify', methods=['POST'])
def pay_notify():
    # Get the raw POST data from PayFast
    raw_body = request.get_data(as_text=True)
    received_signature = request.form.get('signature')

    print("--- PayFast ITN Received ---")
    app.logger.info("--- PayFast ITN Received ---")
    print(f"Raw ITN Body: {raw_body}")
    app.logger.info(f"Raw ITN Body: {raw_body}")
    print(f"Received Signature: {received_signature}")
    app.logger.info(f"Received Signature: {received_signature}")

    # Find the start of the signature in the raw body
    signature_part = "&signature="
    signature_index = raw_body.rfind(signature_part)
    
    # The string to hash is everything BEFORE the signature part
    payload_to_hash = raw_body[:signature_index]
    
    print(f"String to Hash (raw body minus signature): {payload_to_hash}")
    app.logger.info(f"String to Hash (raw body minus signature): {payload_to_hash}")

    # In sandbox, we hash the payload directly (no passphrase).
    # In production, we append the passphrase.
    if not IS_SANDBOX and PAYFAST_PASSPHRASE:
        string_to_check = f"{payload_to_hash}&passphrase={PAYFAST_PASSPHRASE}"
    else:
        string_to_check = payload_to_hash

    print(f"Final String for Hashing: {string_to_check}")
    app.logger.info(f"Final String for Hashing: {string_to_check}")

    calculated_signature = hashlib.md5(string_to_check.encode('utf-8')).hexdigest()
    
    print(f"Calculated Signature: {calculated_signature}")
    app.logger.info(f"Calculated Signature: {calculated_signature}")

    # --- Verification ---
    if calculated_signature != received_signature:
        print("!!! SIGNATURE MISMATCH !!!")
        app.logger.error("!!! PayFast ITN Signature Mismatch !!!")
        return "Invalid signature", 400

    print("--- SIGNATURE VERIFIED ---")
    app.logger.info("--- PayFast ITN Signature Verified ---")

    # --- Process Payment ---
    # Use request.form to get the decoded data for processing
    data = dict(request.form)
    payment_status = data.get('payment_status')
    email = data.get('custom_str1')
    plan = data.get('custom_str2', 'monthly')
    
    if payment_status == 'COMPLETE' and email:
        pf_subscription_id = (
            data.get('pf_subscription_id') or 
            data.get('subscription_id') or 
            data.get('recurring_transaction_id') or 
            data.get('m_payment_id') or 
            ''
        )
        
        app.logger.info(f"Processing COMPLETE payment for {email}, subscription_id: {pf_subscription_id}")
        print(f"Processing COMPLETE payment for {email}, subscription_id: {pf_subscription_id}")
        
        if plan == 'annual':
            subscription_end = datetime.utcnow() + timedelta(days=365)
        else:
            subscription_end = datetime.utcnow() + timedelta(days=30)
        
        update_fields = {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.utcnow(),
            'subscription_end': subscription_end,
            'payment_amount': data.get('amount_gross', '0.00'), # Use amount_gross from ITN
            'payment_id': data.get('pf_payment_id', ''),
            'payfast_subscription_id': pf_subscription_id,
            'last_payment_date': datetime.utcnow()
        }
        
        users_collection.update_one({'email': email}, {'$set': update_fields})
        app.logger.info(f"User {email} upgraded to premium with {plan} plan")
        
    else:
        app.logger.warning(f"Payment status '{payment_status}' for user {email}. No action taken.")
        print(f"Payment status '{payment_status}' for user {email}. No action taken.")
    
    return 'OK', 200

@app.route('/unsubscribe', methods=['POST'])
@login_required
def unsubscribe():
    user = session.get('user')
    if not user:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    db_user = users_collection.find_one({'email': user['email']})
    pf_subscription_id = db_user.get('payfast_subscription_id')
    if not pf_subscription_id:
        return jsonify({'success': False, 'error': 'No active subscription'}), 400

    # Use sandbox or production URL based on environment
    if PAYFAST_SANDBOX:
        cancel_url = 'https://sandbox.payfast.co.za/eng/query/subscription/cancel'
    else:
        cancel_url = 'https://www.payfast.co.za/eng/query/subscription/cancel'
    
    payload = {
          'merchant_id': '25296103',
        'merchant_key': 'rbn0vhdzshrbi',
        'subscription_id': pf_subscription_id
    }
    response = requests.post(cancel_url, data=payload)
    if response.status_code == 200 and 'true' in response.text.lower():
        users_collection.update_one({'email': user['email']}, {'$unset': {'payfast_subscription_id': ""}})
        users_collection.update_one({'email': user['email']}, {'$set': {'premium': False}})
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to cancel subscription'}), 500


def pay_notify_handler(data):
    """Helper function to process PayFast ITN data"""
    payment_status = data.get('payment_status')
    email = data.get('custom_str1')
    plan = data.get('custom_str2', 'monthly')
    
    if payment_status == 'COMPLETE' and email:
        # Get subscription ID from different possible fields
        pf_subscription_id = (
            data.get('pf_subscription_id') or 
            data.get('subscription_id') or 
            data.get('recurring_transaction_id') or 
            data.get('m_payment_id') or 
            ''
        )
        
        app.logger.info(f"Processing payment for {email}, subscription_id: {pf_subscription_id}")
        
        # Calculate subscription end date
        if plan == 'annual':
            subscription_end = datetime.utcnow() + timedelta(days=365)
        else:
            subscription_end = datetime.utcnow() + timedelta(days=30)
        
        # Update user record
        update_fields = {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.utcnow(),
            'subscription_end': subscription_end,
            'payment_amount': data.get('amount', '0.00'),
            'payment_id': data.get('pf_payment_id', ''),
            'last_payment_date': datetime.utcnow()
        }
        
        if pf_subscription_id:
            update_fields['payfast_subscription_id'] = pf_subscription_id
            app.logger.info(f"Subscription ID captured: {pf_subscription_id}")
        else:
            app.logger.warning(f"No subscription ID found in ITN data for {email}")
        
        users_collection.update_one({'email': email}, {'$set': update_fields})
        
        return {'success': True, 'subscription_id': pf_subscription_id}
    
    return {'success': False, 'error': 'Invalid payment status or missing email'}

if __name__ == '__main__':
    # Create static folder if it doesn't exist
    
    app.run(host='0.0.0.0', port=5000)