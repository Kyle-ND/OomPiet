from datetime import timezone,timedelta,datetime,UTC
import pickle
import datetime
import traceback
from xmlrpc.client import _datetime
from bson import ObjectId
from flask import Flask, jsonify, redirect, render_template, request, url_for, session, send_from_directory
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
import requests
import uuid
import base64
import json
import msal
import re
import secrets
import hmac
import hashlib
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash,check_password_hash
import json
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Load environment variables
load_dotenv()
#Auth Utils
from Services.auth import utils as AuthUtils
from Services.auth.utils import login_required
import sys
import logging
from Services.auth import user_auth as UserAuth
from Services.payments import payment_auth as PayAuth
# Email Utils
from Utils.EmailSender import send_contact_email


# Configuration
API_URL = os.getenv('API_URL')
API_KEY = os.getenv('API_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY')  # Default for development
MONGO_URI = os.getenv('MONGO_URI')
MODE = os.getenv('MODE', 'development')

TENANT_ID = os.getenv('TID')
CLIENT_SECRET = os.getenv('CID')

#Microsoft OAuth Configuration
MICROSOFT_CLIENT_ID =  os.getenv('MICROSOFT_CLIENT_ID')
MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
MICROSOFT_TENANT_ID = os.getenv('MICROSOFT_TENANT_ID')
MICROSOFT_REDIRECT_URI = os.getenv('MICROSOFT_REDIRECT_URI')

AUTH_URL = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"

# PayFast Configuration
PAYFAST_MERCHANT_ID = os.getenv('PAYFAST_MERCHANT_ID')
PAYFAST_MERCHANT_KEY = os.getenv('PAYFAST_MERCHANT_KEY')
PAYFAST_PASSPHRASE = os.getenv('PAYFAST_PASSPHRASE', '')
PAYFAST_SANDBOX = os.getenv('PAYFAST_SANDBOX', 'true').lower() == 'true'

app = Flask(__name__, static_folder='static')

# Load backend subdomain from environment
BACKEND_SUBDOMAIN = os.getenv('BACKEND_SUBDOMAIN', 'https://api.mentormate.co.za')

# --- CORS: Strict, explicit origins, credentials allowed ---
CORS(
    app,
    origins=[
        "https://mentormate-client.vercel.app",
        "https://mentormate.co.za",
        "https://www.mentormate.co.za",
        "https://www.mentormate.co.za/upload",
        BACKEND_SUBDOMAIN,
        "http://localhost:3000"
    ],
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "Accept"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    expose_headers=["Set-Cookie"],
    max_age=3600
)



app.secret_key = SECRET_KEY

# MongoDB Setup (must be before session config for MongoDB sessions)
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)

# Configure server-side sessions with MongoDB for Railway container compatibility
app.config['SESSION_TYPE'] = 'mongodb'
app.config['SESSION_MONGODB'] = client
app.config['SESSION_MONGODB_DB'] = 'geotech_db'
app.config['SESSION_MONGODB_COLLECT'] = 'flask_sessions'

# --- Session Cookie: Secure, cross-site, robust for all browsers ---
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Required for cross-site cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Required for production HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
# CRITICAL: Removed SESSION_COOKIE_DOMAIN to let browser set cookie for exact host
# Setting Domain=.mentormate.co.za causes issues with cross-origin requests
# app.config['SESSION_COOKIE_DOMAIN'] = '.mentormate.co.za'


# Initialize Flask-Session (server-side sessions)
Session(app)

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
app.logger.setLevel(logging.INFO)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
db = client["geotech_db"]
users_collection = db["users"]
dashboard_stats_collection = db["dashboard_stats"]
feedback_collection = db["feedback"]
sessions_collection = db["sessions"]
password_reset_collection = db["password_reset_tokens"]
collection = db["rag_queries"]


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

# Configure Microsoft OAuth
microsoft = oauth.register(
    name='microsoft',
    client_id=MICROSOFT_CLIENT_ID,
    client_secret=MICROSOFT_CLIENT_SECRET,  
    authorize_url=f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    authorize_params=None,
    access_token_url=f'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=MICROSOFT_REDIRECT_URI,
    client_kwargs={
        'scope': 'openid email profile User.Read',
        'token_endpoint_auth_method': 'client_secret_post',
    },
    # NOTE: Not using server_metadata_url with /common because it causes issuer validation errors
    # We manually exchange the authorization code for tokens in the callback handler
)

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USERNAME)


# Valid collections accepted by the RAG service
ALLOWED_QDRANT_COLLECTIONS = [
    "Concrete_docs",
    "Tailings_engineer_docs", 
    "Water_docs",
    "Mining_docs",
    "Electrical_docs"
]

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)



# Start cleanup scheduler
# schedule_cleanup()
AuthUtils.schedule_cleanup() 


# --- Partitioned attribute: Only for Chrome/Brave, not for Safari/Firefox ---
def add_partitioned_to_cookies(response):
    """
    Add Partitioned attribute to session cookies for Chrome/Brave (not Safari/Firefox).
    """
    cookies = response.headers.getlist('Set-Cookie')
    if not cookies:
        return response
    response.headers.remove('Set-Cookie')
    session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
    modified = False
    for cookie in cookies:
        # ...existing code for add_partitioned_to_cookies...
        if session_cookie_name in cookie:
            # Only add Partitioned if not present and not on Safari/Firefox
            if 'Partitioned' not in cookie and 'partitioned' not in cookie.lower():
                cookie = cookie.rstrip(';').rstrip() + '; Partitioned'
                modified = True
        response.headers.add('Set-Cookie', cookie)
    if modified:
        app.logger.debug("✓ Added Partitioned attribute to session cookie")
    return response

# --- Limiter: Flask-Limiter instance ---
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
)

# --- User dashboard stats initializer ---
def initialize_new_user_dashboard_stats(email):
    stats = {
        "user_email": email,
        "total_chats": 0,
        "total_messages": 0,
        "last_active": datetime.datetime.now(timezone.utc),
        "created_at": datetime.datetime.now(timezone.utc)
    }
    dashboard_stats_collection.insert_one(stats)
    return stats

"""I will remove this function once we have a dedicated Util func"""
def get_login_identifier():
    ip = get_remote_address()
    if request.method == "POST":
        username = request.form.get("username", "no-username")
        return f"{ip}:{username}"
    return ip

# --- Modified Signup Endpoint ---
@app.route('/api/signup', methods=['POST'])
@limiter.limit("3 per minute",  key_func= get_login_identifier,error_message="Too many signup's. Please wait a moment and try again.")
def signup():
    return UserAuth.handle_signup(users_collection, initialize_new_user_dashboard_stats)



@app.route('/api/check-session', methods=['GET'])
def check_session():
    """Check if user has active session"""
    # DIAGNOSTIC LOGGING - Log only specific safe headers, not all headers
    app.logger.info(f"🔍 check-session called")
    
    # Log what cookies the browser sent in request
    app.logger.info(f"   - request.cookies keys: {list(request.cookies.keys())}")
    app.logger.info(f"   - request.cookies: {dict(request.cookies)}")
    
    # Log only safe headers (not Authorization, API keys, tokens, etc.)
    safe_headers = {
        'Cookie': request.headers.get('Cookie', 'NONE'),
        'User-Agent': request.headers.get('User-Agent', 'NONE')
    }
    # Truncate cookie header for readability
    if safe_headers['Cookie'] != 'NONE':
        safe_headers['Cookie'] = safe_headers['Cookie'][:100] + '...' if len(safe_headers['Cookie']) > 100 else safe_headers['Cookie']
    app.logger.info(f"   - Request headers (safe): {safe_headers}")
    
    # CRITICAL FIX: Handle multiple cookies with same name
    # Browser may send multiple 'google-login-session' cookies
    # We need to try ALL of them, not just the first one Flask loads
    cookie_header = request.headers.get('Cookie', '')
    app.logger.info(f"   - Cookie header: {cookie_header[:200] if cookie_header else 'EMPTY'}")
    
    cookie_name = app.config['SESSION_COOKIE_NAME']
    app.logger.info(f"   - Cookie name expected: {cookie_name}")
    app.logger.info(f"   - SESSION_COOKIE_NAME config value: {cookie_name}")
    
    # Extract all cookies with our session name
    import re
    pattern = rf'{cookie_name}=([^;]+)'
    all_session_cookies = re.findall(pattern, cookie_header)
    app.logger.info(f"   - Found {len(all_session_cookies)} cookies named {cookie_name}")
    
    is_authenticated = 'user' in session
    user_data = session.get('user', None)
    app.logger.info(f"   - Flask session has 'user': {is_authenticated}")
    app.logger.info(f"   - Flask session keys: {list(session.keys())}")
    app.logger.info(f"   - Flask session.sid: {getattr(session, 'sid', 'NO SID')}")
    # Log only that user data is present, not the actual data (privacy/security)
    is_user_present = bool(user_data)
    app.logger.info(f"   - User data present: {is_user_present}")
    
    # CRITICAL FIX: If current session is empty, try other cookies
    if not is_authenticated and len(all_session_cookies) > 1:
        if app.config.get('SESSION_TYPE') == 'mongodb':
            try:
                session_collection = client['geotech_db']['flask_sessions']
                
                # Try each cookie to find one with user data
                for idx, cookie_value in enumerate(all_session_cookies):
                    session_id = cookie_value.split('.')[0]
                    
                    # Look up in MongoDB
                    found_session = session_collection.find_one({"id": session_id})
                    
                    if found_session and found_session.get('val'):
                        # Deserialize session data
                        # SECURITY NOTE: Flask-Session uses pickle - see security comment in verify_session_token
                        session_data = pickle.loads(found_session['val'])
                        
                        if 'user' in session_data:
                            is_authenticated = True
                            user_data = session_data['user']
                            break
                        
            except Exception as e:
                app.logger.error(f"Error checking alternate cookies: {e}")
    
    # Parse name into firstName/lastName for frontend compatibility
    if is_authenticated and user_data and isinstance(user_data, dict):
        name = user_data.get('name', '')
        name_parts = name.split(' ', 1)
        user_data['firstName'] = name_parts[0] if name_parts else ''
        user_data['lastName'] = name_parts[1] if len(name_parts) > 1 else ''
    
    response_data = {
        'authenticated': is_authenticated,
        'user': user_data
    }
    
    return jsonify(response_data), 200

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


@app.route('/api/verify-session-token', methods=['POST'])
def verify_session_token():
    """
    FALLBACK: When cookies are blocked, frontend can send session_token from localStorage
    This endpoint looks up the session in MongoDB and sets a cookie if valid
    """
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        
        if not session_token:
            return jsonify({'authenticated': False, 'error': 'No session token provided'}), 400
        
        app.logger.info(f"🔑 Verifying session token from localStorage: {session_token[:20]}...")
        
        # Look up session in MongoDB
        session_collection = client['geotech_db']['flask_sessions']
        found_session = session_collection.find_one({"id": session_token})
        
        if not found_session or not found_session.get('val'):
            app.logger.warning(f"Session token not found in MongoDB: {session_token[:20]}")
            return jsonify({'authenticated': False, 'error': 'Invalid or expired session'}), 401
        
        # Check if session is expired
        if found_session.get('expiration'):
            expiration = found_session['expiration']
            if expiration < datetime.datetime.now(timezone.utc):
                app.logger.warning(f"Session token expired: {session_token[:20]}")
                return jsonify({'authenticated': False, 'error': 'Session expired'}), 401
        
        # Deserialize session data
        # SECURITY: Using JSON instead of pickle to prevent arbitrary code execution
        # JSON is safe and only supports basic data types (str, int, bool, list, dict)
        try:
            raw_val = found_session['val']
            # Ensure JSON deserialization always receives text, not raw bytes
            if isinstance(raw_val, bytes):
                raw_val = raw_val.decode('utf-8')
            session_data = json.loads(raw_val)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
            # Fallback to pickle for legacy sessions (will be phased out)
            app.logger.warning(f"Legacy pickle session detected: {session_token[:20]}")
            legacy_val = found_session['val']
            # Ensure pickle deserialization receives bytes
            if isinstance(legacy_val, str):
                legacy_val = legacy_val.encode('utf-8')
            session_data = pickle.loads(legacy_val)
        
        if 'user' not in session_data:
            app.logger.warning(f"Session has no user data: {session_token[:20]}")
            return jsonify({'authenticated': False, 'error': 'Invalid session'}), 401
        
        # Set session data
        session.clear()
        session.permanent = True
        session['user'] = session_data['user']
        session['session_id'] = session_data.get('session_id')
        session.modified = True
        
        app.logger.info(f"✓ Session restored from localStorage for {session_data['user']['email']}")
        
        # Parse name for frontend
        user_data = session_data['user']
        name = user_data.get('name', '')
        name_parts = name.split(' ', 1)
        user_data['firstName'] = name_parts[0] if name_parts else ''
        user_data['lastName'] = name_parts[1] if len(name_parts) > 1 else ''
        
        return jsonify({
            'authenticated': True,
            'user': user_data,
            'message': 'Session restored from localStorage'
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error verifying session token: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'authenticated': False, 'error': 'Internal error'}), 500


@app.route('/api/signin', methods=['POST'])
@limiter.limit("5 per minute",  key_func= get_login_identifier, error_message="Too many login attempts. Please wait a moment and try again.")
@limiter.limit("10 per minute",  key_func= get_remote_address, error_message="Too many login attempts. Please wait a moment and try again.")
def signin():
    return UserAuth.handle_signin(users_collection)




# Password Reset Endpoints
@app.route('/api/forgot-password', methods=['POST'])
@limiter.limit("5 per hour", key_func=get_login_identifier, error_message="Too many attempts. Please wait a moment and try again.")
@limiter.limit("5 per hour", key_func=get_remote_address)
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    return UserAuth.handle_recover_password(users_collection,email)


@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("5 per hour", key_func=get_remote_address, error_message="Changed password too many times. Please wait a moment and try again.")
def reset_password():
    return UserAuth.handle_reset_password(users_collection)


@app.route('/login')
@app.route('/login/google')
def login():
    """Google OAuth login - VERIFIED for cross-site cookies"""
    try:
        app.logger.info(f"🔐 Google OAuth login initiated - MODE={MODE}")
        app.logger.info(f"📧 Google Client ID: {GOOGLE_CLIENT_ID[:30] if GOOGLE_CLIENT_ID else 'NOT SET'}...")
        
        # Get old session ID BEFORE clearing
        old_cookie = request.cookies.get(app.config['SESSION_COOKIE_NAME'], '')
        old_sid = old_cookie.split('.')[0] if old_cookie else None
        
        # Delete old sessions from MongoDB
        if old_sid:
            try:
                session_collection = client['geotech_db']['flask_sessions']
                existing = session_collection.find_one({"id": old_sid})
                if existing:
                    session_collection.delete_one({"id": old_sid})
                    app.logger.info(f"Deleted old session: {old_sid[:20]}...")
            except Exception as e:
                app.logger.warning(f"Could not delete old session: {e}")
        
        # Clear session (generates new ID)
        session.clear()

        if MODE == 'development':
            redirect_url = "http://localhost:3000/auth/google/callback"
        else:
            redirect_url = "https://mentormate.co.za/auth/google/callback"

        # Create stateless state parameter (doesn't rely on session/cookies)
        # This works even when browsers block cookies during OAuth redirect
        state_data = {
            'redirect_url': redirect_url,
            'provider': 'google',
            'timestamp': datetime.datetime.now(timezone.utc).isoformat(),
            'nonce': secrets.token_urlsafe(16)
        }
        
        # Encode and sign state to prevent tampering
        state_json = json.dumps(state_data)
        state_b64 = base64.urlsafe_b64encode(state_json.encode()).decode()
        
        # Sign state with secret key to prevent tampering
        if isinstance(app.secret_key, bytes):
            secret_key_bytes = app.secret_key
        elif isinstance(app.secret_key, str):
            secret_key_bytes = app.secret_key.encode()
        else:
            secret_key_bytes = str(app.secret_key).encode() if app.secret_key else b'default-secret'
        signature = hmac.new(
            secret_key_bytes,
            state_b64.encode(),
            hashlib.sha256
        ).hexdigest()[:16]  # Use first 16 chars
        
        # Combine state and signature
        signed_state = f"{state_b64}.{signature}"
       
        # Construct redirect_uri explicitly based on MODE
        if MODE == 'development':
            redirect_uri = "http://localhost:5000/google/callback"
        else:
            redirect_uri = "https://api.mentormate.co.za/google/callback"
        
        app.logger.info(f"🔗 Redirect URI: {redirect_uri}")
        
        # Pass signed state to OAuth provider
        # We override Authlib's state management completely
        response = google.authorize_redirect(redirect_uri=redirect_uri, state=signed_state)
        app.logger.info(f"✅ OAuth redirect created successfully")
        
    except Exception as e:
        app.logger.error(f"❌ Google OAuth Error: {str(e)}")
        app.logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return jsonify({
            "error": "Google OAuth initialization failed",
            "details": str(e),
            "message": "Please contact support or check server logs"
        }), 500
    
    # Force session save
    session.modified = True
    try:
        app.session_interface.save_session(app, session, response)
        
        # Verify cookie was set
        cookie_header = response.headers.get('Set-Cookie', '')
        if 'google-login-session=' in cookie_header:
            cookie_value = cookie_header.split('google-login-session=')[1].split(';')[0]
            session_id = cookie_value.split('.')[0] if '.' in cookie_value else cookie_value
            
            # Force MongoDB write
            session_collection = client['geotech_db']['flask_sessions']
            
            
            session_doc = {
                'id': session_id,
                'val': pickle.dumps(dict(session)),
                'expiration': datetime.datetime.now(timezone.utc) + timedelta(minutes=60)
            }
            
            result = session_collection.replace_one(
                {'id': session_id},
                session_doc,
                upsert=True
            )
            
            if result.acknowledged:
                app.logger.info(f"✓ Session saved: {session_id[:20]}...")
            else:
                app.logger.error(f"✗ Session save not acknowledged!")
            
    except Exception as e:
        app.logger.error(f"Session save failed: {e}")
    
    return response

@app.route('/login/microsoft')
def microsoft_login():
    """Microsoft OAuth login - VERIFIED for cross-site cookies"""
    try:
        app.logger.info(f"🔐 Microsoft OAuth login initiated - MODE={MODE}")
        app.logger.info(f"📧 Microsoft Client ID: {MICROSOFT_CLIENT_ID[:30] if MICROSOFT_CLIENT_ID else 'NOT SET'}...")
        
        # Same pattern as Google login above
        old_cookie = request.cookies.get(app.config['SESSION_COOKIE_NAME'], '')
        old_sid = old_cookie.split('.')[0] if old_cookie else None
        
        if old_sid:
            try:
                session_collection = client['geotech_db']['flask_sessions']
                existing = session_collection.find_one({"id": old_sid})
                if existing:
                    session_collection.delete_one({"id": old_sid})
                    app.logger.info(f"Deleted old session: {old_sid[:20]}...")
            except Exception as e:
                app.logger.warning(f"Could not delete old session: {e}")
        
        session.clear()
        if MODE == 'development':
            redirect_url = "http://localhost:3000/microsoft-callback"
        else:
            redirect_url = "https://mentormate.co.za/microsoft-callback"

        # Create stateless state parameter (doesn't rely on session/cookies)
        state_data = {
            'redirect_url': redirect_url,
            'provider': 'microsoft',
            'timestamp': datetime.datetime.now(timezone.utc).isoformat(),
            'nonce': secrets.token_urlsafe(16)
        }
        
        # Encode and sign state
        state_json = json.dumps(state_data)
        state_b64 = base64.urlsafe_b64encode(state_json.encode()).decode()
        
        if isinstance(app.secret_key, bytes):
            secret_key_bytes = app.secret_key
        elif isinstance(app.secret_key, str):
            secret_key_bytes = app.secret_key.encode()
        else:
            secret_key_bytes = str(app.secret_key).encode() if app.secret_key else b'default-secret'
        signature = hmac.new(
            secret_key_bytes,
            state_b64.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        signed_state = f"{state_b64}.{signature}"
        
        # Construct redirect_uri explicitly based on MODE
        if MODE == 'development':
            redirect_uri = "http://localhost:5000/microsoft/callback"
        else:
            redirect_uri = "https://api.mentormate.co.za/microsoft/callback"
        
        app.logger.info(f"🔗 Redirect URI: {redirect_uri}")
        
        response = microsoft.authorize_redirect(redirect_uri=redirect_uri, state=signed_state)
        app.logger.info(f"✅ OAuth redirect created successfully")
        
    except Exception as e:
        app.logger.error(f"❌ Microsoft OAuth Error: {str(e)}")
        app.logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return jsonify({
            "error": "Microsoft OAuth initialization failed",
            "details": str(e),
            "message": "Please contact support or check server logs"
        }), 500
    
    session.modified = True
    try:
        app.session_interface.save_session(app, session, response)
        
        cookie_header = response.headers.get('Set-Cookie', '')
        if 'google-login-session=' in cookie_header:
            cookie_value = cookie_header.split('google-login-session=')[1].split(';')[0]
            session_id = cookie_value.split('.')[0] if '.' in cookie_value else cookie_value
            
            session_collection = client['geotech_db']['flask_sessions']
            
            
            session_doc = {
                'id': session_id,
                'val': pickle.dumps(dict(session)),
                'expiration': datetime.datetime.now(timezone.utc) + timedelta(minutes=60)
            }
            
            result = session_collection.replace_one(
                {'id': session_id},
                session_doc,
                upsert=True
            )
            
            if result.acknowledged:
                app.logger.info(f"✓ Session saved: {session_id[:20]}...")
            else:
                app.logger.error(f"✗ Session save not acknowledged!")
            
    except Exception as e:
        app.logger.error(f"Session save failed: {e}")
    
    return response



@app.route('/microsoft/callback')
def microsoft_callback():
    """Handle Microsoft OAuth callback"""
    return UserAuth.handle_microsoft_callback(microsoft, users_collection, initialize_new_user_dashboard_stats)


@app.route('/google/callback')
def google_callback():
    """Handle Google OAuth callback - Authlib validates state automatically"""
    # Authlib automatically validates state parameter against session
    # No need for manual state validation here
    return UserAuth.handle_google_callback(google,users_collection,initialize_new_user_dashboard_stats)

@app.route('/check-login-status')
def check_login_status():
    user = session.get('user')
    if user:
        return jsonify({'loggedIn': True})
    return jsonify({'loggedIn': False})

@app.route('/api/user-profile')
def user_profile():
    return UserAuth.handle_user_profile(users_collection, db)

@app.route('/check-upload-access')
def check_upload_access():
    if session.get('upload_access'):
        return jsonify({'uploadAccess': True})
    return jsonify({'uploadAccess': False})

@app.route('/logout', methods=['POST', 'GET'])
@app.route('/signout', methods=['POST', 'GET'])  # Support both endpoints for frontend compatibility
def logout():
    user_email = session.get('user', {}).get('email')
    if user_email:
        AuthUtils.remove_user_session(user_email)
    
    # CRITICAL: Must call session.clear() to completely remove session from MongoDB
    # This ensures no stale session data persists
    session.clear()
    
    # Create response
    if request.method == 'POST' or request.headers.get('Content-Type') == 'application/json':
        response = jsonify({"success": True, "message": "Logged out successfully"})
    else:
        response = redirect("https://mentormate.co.za/mentormate-homepage")
    
    # CRITICAL: Explicitly delete the session cookie by setting Max-Age=0
    # This prevents duplicate cookie issues on re-login
    response.set_cookie(
        app.config['SESSION_COOKIE_NAME'],
        value='',
        max_age=0,
        secure=True,
        httponly=True,
        samesite='None',
        path='/'
    )
    
    app.logger.info("Logout: Session cleared and cookie deleted")
    return response

# Template routes removed - React frontend handles all UI

@app.route('/api/feedback', methods=['POST', 'OPTIONS'])
@login_required
def submit_feedback():
    return UserAuth.handle_feed_back(feedback_collection, dashboard_stats_collection)

@app.route('/api/invalidate-session', methods=['POST'])
def invalidate_session():
    """Invalidate current session (called when user logs in from another device)"""
    return UserAuth.handle_invalidate_session()

# Session conflict route removed - React frontend handles this via API

@app.route('/api/force-login', methods=['POST'])
def force_login():
    """Force login by logging out the previous session"""
    return UserAuth.handle_login(users_collection)

@app.route('/pay')
@login_required
@limiter.limit("5 per hour", key_func=get_remote_address)
def pay():
    return PayAuth.payment_op()

@app.route('/pay/success')
@login_required
def pay_success():
    return PayAuth.payment_successful(users_collection)

@app.route('/pay/cancel')
@login_required
def pay_cancel():
    # Redirect to React frontend with cancellation message
    return redirect("https://mentormate.co.za/payment-cancelled")

@app.route('/pay/notify', methods=['POST'])
def pay_notify():
    return PayAuth.payment_notification(users_collection, PAYFAST_SANDBOX, PAYFAST_PASSPHRASE)

@app.route('/unsubscribe', methods=['POST'])
@login_required
def unsubscribe():
    return UserAuth.handle_unsubscription(users_collection, PAYFAST_SANDBOX)


@app.route("/chat_history/<user_id>", methods=["GET"])
@login_required
def get_history_chat(user_id):
    # SECURITY: Verify user_id matches authenticated user
    auth_user = session.get('user', {})
    auth_user_id = auth_user.get('id') or auth_user.get('email')
    
    if user_id != auth_user_id:
        return jsonify({"error": "Unauthorized: Cannot access other users' chat history"}), 403
    
    try:
        collection_name = request.args.get("collection_name")
        limit = request.args.get("limit", type=int)

        # Build a conversation_id pattern for this user and match any conversation
        # belonging to this user (e.g. conv_<user_id> or conv_<user_id>_xxxx)
        # Escape the user_id for safe regex construction
        conversation_id_pattern = f"^conv_{re.escape(user_id)}"

        # MongoDB query - use a regex so we capture all user's conversations
        query = {"conversation_id": {"$regex": conversation_id_pattern}}

        if collection_name and collection_name in ALLOWED_QDRANT_COLLECTIONS:
            query["collection_name"] = collection_name

        #Group messages by conversation_id
        pipeline = [
            {"$match": query},
            {"$sort": {"timestamp":1}},
            {
                "$group":{
                    "_id": {
                        "conversation_id": "$conversation_id",
                        "collection_name": "$collection_name"
                    },
                    "created_at": {"$min": "$timestamp"},
                    "last_activity": {"$max": "$timestamp"},
                    "message_count": {"$sum": 1},
                    "messages": {
                        "$push": {
                            "query": "$query",
                            "answer": "$answer",
                            "timestamp": "$timestamp",
                            "model_used": "$model_used",
                            "is_new_conversation": "$is_new_conversation",
                            "role": "$role"
                        }
                    }
                }
            },
            {"$sort": {"last_activity": -1}}
        ]

        #Add limit if specified
        if limit:
            pipeline.append({"$limit": limit})

        sessions = list(collection.aggregate(pipeline))



        # Format response
        response = {
            "user_id": user_id,
            # total sessions should reflect DB results, not the Flask `session` object
            "total_session": len(sessions),
            "session": []
        }

        for session_data in sessions:
            formatted_session = {
                "session_id": session_data["_id"]["conversation_id"],
                "collection_name": session_data["_id"]["collection_name"],
                "created_at": session_data["created_at"].isoformat() if session_data.get("created_at") else None,
                "last_activity": session_data["last_activity"].isoformat() if session_data.get("last_activity") else None,
                "message_count": session_data["message_count"],
                "messages": []
            }

            #Format messages
            for msg in session_data["messages"]:
                formatted_session["messages"].append({
                    "query": msg.get("query"),
                    "answer": msg.get("answer"),
                    "timestamp": msg.get("timestamp").isoformat() if isinstance(msg.get("timestamp"), datetime.datetime) else (str(msg.get("timestamp")) if msg.get("timestamp") else None),
                    "model_used": msg.get("model_used"),
                    "role": msg.get("role")
                })
            
            # Add share status (check first message of conversation)
            formatted_session["is_shared"] = session_data["messages"][0].get("is_shared", False) if session_data["messages"] else False

            # Append this formatted session into the response list
            response["session"].append(formatted_session)

        return jsonify(response), 200
    except Exception as e:
        app.logger.error(f"Error fetching chat history: {str(e)}")
        return jsonify({"error": "Failed to fetch chat history"}), 500
    

@app.route("/chat_history/<user_id>/session/<conversation_id>", methods=["GET"])
@login_required
def get_specific_session(user_id, conversation_id):
    # SECURITY: Verify user_id matches authenticated user
    auth_user = session.get('user', {})
    auth_user_id = auth_user.get('id') or auth_user.get('email')

    # Normalize IDs to prevent case-sensitivity bypass (e.g., with email addresses)
    normalized_user_id = (str(user_id).strip().lower()) if user_id is not None else None
    normalized_auth_user_id = (str(auth_user_id).strip().lower()) if auth_user_id is not None else None

    if not normalized_auth_user_id or normalized_user_id != normalized_auth_user_id:
        return jsonify({"error": "Unauthorized: Cannot access other users' sessions"}), 403
    
    try:
        # Verify the conversation belongs to this user (conversation ids start with conv_<user_id>)
        expected_prefix = f"conv_{user_id}"
        if not conversation_id.startswith(expected_prefix):
            return jsonify({"error": "Conversation ID does not match user ID"}), 403
        
        # Check if user wants to include retrieved chunks
        include_chunks = request.args.get('include_chunks', 'false').lower() == 'true'
        
        # Fetch all messages for this conversation
        messages = list(collection.find(
            {"conversation_id": conversation_id}
        ).sort("timestamp", 1))
        
        if not messages:
            return jsonify({
                "session_id": conversation_id,
                "user_id": user_id,
                "message_count": 0,
                "messages": []
            }), 200
        
        # Format response
        response = {
            "session_id": conversation_id,
            "user_id": user_id,
            "collection_name": messages[0].get("collection_name"),
            "created_at": messages[0].get("timestamp").isoformat() if isinstance(messages[0].get("timestamp"), datetime.datetime) else (str(messages[0].get("timestamp")) if messages[0].get("timestamp") else None),
            "last_activity": messages[-1].get("timestamp").isoformat() if isinstance(messages[-1].get("timestamp"), datetime.datetime) else (str(messages[-1].get("timestamp")) if messages[-1].get("timestamp") else None),
            "message_count": len(messages),
            "messages": []
        }
        
        for msg in messages:
            message_data = {
                "query": msg.get("query"),
                "answer": msg.get("answer"),
                "timestamp": msg.get("timestamp").isoformat() if isinstance(msg.get("timestamp"), datetime.datetime) else (str(msg.get("timestamp")) if msg.get("timestamp") else None),
                "model_used": msg.get("model_used"),
                "is_new_conversation": msg.get("is_new_conversation"),
                "role": msg.get("role")
            }
            
            # Optionally include retrieved chunks
            if include_chunks:
                message_data["retrieved_chunks"] = msg.get("retrieved_chunks", [])
            
            response["messages"].append(message_data)
        
        return jsonify(response), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching specific session: {str(e)}")
        return jsonify({"error": "Failed to fetch session"}), 500
    

@app.route("/chat_history/<user_id>/delete", methods=["DELETE"])
@login_required
def delete_chat_history(user_id):
    # SECURITY: Verify user_id matches authenticated user (normalize to prevent case-based bypass)
    auth_user = session.get('user', {})
    auth_user_id = auth_user.get('id') or auth_user.get('email')
    
    normalized_path_user_id = str(user_id).strip().lower()
    normalized_auth_user_id = str(auth_user_id).strip().lower() if auth_user_id is not None else None
    
    if normalized_auth_user_id is None or normalized_path_user_id != normalized_auth_user_id:
        return jsonify({"error": "Unauthorized: Cannot delete other users' chat history"}), 403
    
    try:
        conversation_id_param = request.args.get('conversation_id')
        collection_name_filter = request.args.get('collection_name')
        
        # Build delete query
        if conversation_id_param:
            # Delete specific session - verify it belongs to user
            expected_prefix = f"conv_{user_id}"
            
            if not conversation_id_param.startswith(expected_prefix):
                return jsonify({"error": "Conversation ID does not match user ID"}), 403

            query = {"conversation_id": conversation_id_param}
        else:
            # Delete all sessions for user (match any conversation starting with conv_<user_id>)
            query = {"conversation_id": {"$regex": f"^conv_{re.escape(user_id)}"}}
        
        # Add collection filter if specified and valid
        if collection_name_filter and collection_name_filter in ALLOWED_QDRANT_COLLECTIONS:
            query["collection_name"] = collection_name_filter
        
        # Execute deletion
        result = collection.delete_many(query)
        
        return jsonify({
            "status": "success",
            "deleted_count": result.deleted_count,
            "user_id": user_id
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting chat history: {str(e)}")
        return jsonify({"error": "Failed to delete history"}), 500


@app.route('/api/rag', methods=['POST'])
def proxy_rag():
    # Check authentication
    if 'user' not in session:
        return jsonify({
            "error": "Authentication required",
            "message": "Please login first using /api/signin or OAuth"
        }), 401

    try:
        data = request.get_json() or {}
        query_text = data.get('query')
        collection_name = data.get('collection_name')
        
        # Validate collection_name
        if not collection_name:
            return jsonify({"error": "collection_name is required"}), 400
        
        if collection_name not in ALLOWED_QDRANT_COLLECTIONS:
            return jsonify({
                "error": f"Invalid collection_name '{collection_name}'. Must be one of: {', '.join(ALLOWED_QDRANT_COLLECTIONS)}"
            }), 400

        # Use authenticated user's id/email to prevent spoofing.
        auth_user = session.get('user', {})
        user_id = auth_user.get('id') or auth_user.get('email') or 'unknown'
        conversation_id = data.get('conversation_id')

        # Generate a new conversation id if not provided
        # CRITICAL: Include collection_name to keep each mentor's conversations separate
        is_new = False
        if not conversation_id:
            # Include collection_name in conversation ID to separate mentors
            conversation_id = f"conv_{user_id}_{collection_name}_{uuid.uuid4().hex[:8]}"
            is_new = True
        else:
            # Validate conversation_id ownership and collection match
            # Accept conversation IDs that belong to this user and collection
            expected_user_prefix = f"conv_{user_id}_"
            
            if not str(conversation_id).startswith(expected_user_prefix):
                # Security: Reject conversations from other users
                app.logger.warning(f"Rejected conversation_id {conversation_id} - doesn't belong to user {user_id}")
                conversation_id = f"conv_{user_id}_{collection_name}_{uuid.uuid4().hex[:8]}"
                is_new = True
            else:
                # CRITICAL FIX: Verify the collection_name matches to prevent cross-mentor conversation leaks
                # Extract collection from conversation ID: conv_{user}_{collection}_{random}
                parts = conversation_id.split('_', 3)  # Split into max 4 parts
                if len(parts) >= 3:
                    conv_collection = parts[2]
                    # Check if this is a valid collection name (new format) or random ID (old format)
                    if conv_collection in ALLOWED_QDRANT_COLLECTIONS:
                        # NEW FORMAT: conv_{user}_{collection}_{random}
                        if conv_collection != collection_name:
                            # CRITICAL: User is trying to use a conversation from a different mentor
                            # This causes cross-mentor memory leak - FORCE new conversation
                            app.logger.warning(f"BLOCKED cross-mentor leak: conversation has {conv_collection}, request has {collection_name} - creating new conversation")
                            conversation_id = f"conv_{user_id}_{collection_name}_{uuid.uuid4().hex[:8]}"
                            is_new = True
                        # else: Valid conversation ID with matching collection - continue it!
                    else:
                        # OLD FORMAT: conv_{user}_{random}
                        # Check MongoDB to see which collection this conversation belongs to
                        try:
                            existing_msg = collection.find_one({"conversation_id": conversation_id})
                            if existing_msg:
                                existing_collection = existing_msg.get("collection_name")
                                if existing_collection and existing_collection != collection_name:
                                    # CRITICAL: Old format conversation from different mentor - FORCE new conversation
                                    app.logger.warning(f"BLOCKED cross-mentor leak: old format conversation has {existing_collection}, request has {collection_name} - creating new conversation")
                                    conversation_id = f"conv_{user_id}_{collection_name}_{uuid.uuid4().hex[:8]}"
                                    is_new = True
                                # else: Same collection or no collection_name - allow continuation
                            # else: Conversation doesn't exist yet - allow continuation
                        except Exception as db_exc:
                            app.logger.error(f"Error checking conversation collection: {db_exc}")
                            # On error, be safe and create new conversation
                            conversation_id = f"conv_{user_id}_{collection_name}_{uuid.uuid4().hex[:8]}"
                            is_new = True
                else:
                    # Malformed conversation ID - create new one
                    app.logger.warning(f"Malformed conversation_id detected, creating new one")
                    conversation_id = f"conv_{user_id}_{collection_name}_{uuid.uuid4().hex[:8]}"
                    is_new = True

        # Basic validation
        if not query_text:
            return jsonify({"error": "query is required"}), 400

        # Forward to external RAG service (configurable via RAG_SERVICE_URL)
        rag_url = os.getenv('RAG_SERVICE_URL') or 'https://oompiet.space/rag'
        forward_payload = data.copy()
        forward_payload['conversation_id'] = conversation_id
        forward_payload['user_id'] = user_id

        # Persist the user's message first (so we always have the user's side recorded)
        now = datetime.datetime.now(timezone.utc)
        try:
            user_doc = {
                "conversation_id": conversation_id,
                "collection_name": collection_name,
                "timestamp": now,
                "query": query_text,
                "answer": None,
                "model_used": None,
                "is_new_conversation": is_new,
                "role": "user"
            }
            collection.insert_one(user_doc)
        except Exception as db_exc:
            app.logger.exception("Error saving user message to rag_queries")

        try:
            resp = requests.post(rag_url, json=forward_payload, timeout=30)
            resp.raise_for_status()
            resp_json = resp.json()
        except requests.exceptions.HTTPError as http_err:
            # Log the actual error response from RAG service
            app.logger.error(f"RAG service returned {http_err.response.status_code}: {http_err.response.text}")
            resp_json = {"error": f"RAG service error: {http_err.response.text}"}
        except Exception as exc:
            # If forwarding failed, log and return error; user message is already persisted
            app.logger.exception("Error forwarding to RAG service")
            resp_json = {"error": str(exc)}

        # Persist the assistant reply if available
        try:
            if isinstance(resp_json, dict) and resp_json.get('answer'):
                assistant_doc = {
                    "conversation_id": conversation_id,
                    "collection_name": collection_name,
                    "timestamp": datetime.datetime.now(timezone.utc),
                    "query": None,
                    "answer": resp_json.get('answer'),
                    "model_used": resp_json.get('model_used'),
                    "is_new_conversation": False,
                    "role": "assistant"
                }
                collection.insert_one(assistant_doc)
        except Exception as db_exc:
            app.logger.exception("Error saving assistant message to rag_queries")

        # Ensure the response contains the conversation id so client can continue
        if isinstance(resp_json, dict):
            resp_json['conversation_id'] = conversation_id

        status_code = 200 if isinstance(resp_json, dict) and not resp_json.get('error') else 500
        return jsonify(resp_json), status_code

    except Exception as e:
        app.logger.error(f"Error in /api/rag proxy: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/rag/sessions', methods=['GET'])
@login_required
def list_rag_sessions():
  
    try:
        auth_user = session.get('user', {})
        user_id = auth_user.get('id') or auth_user.get('email')
        if not user_id:
            return jsonify({"error": "Authenticated user id not found in session"}), 403

        collection_name = request.args.get('collection_name')
        limit = request.args.get('limit', type=int) or 20

        match = {"conversation_id": {"$regex": f"^conv_{user_id}"}}
        if collection_name and collection_name in ALLOWED_QDRANT_COLLECTIONS:
            match["collection_name"] = collection_name

        pipeline = [
            {"$match": match},
            {"$group": {
                "_id": "$conversation_id",
                "created_at": {"$min": "$timestamp"},
                "last_activity": {"$max": "$timestamp"},
                "message_count": {"$sum": 1},
                "collection_name": {"$first": "$collection_name"}
            }},
            {"$sort": {"last_activity": -1}},
            {"$limit": limit}
        ]

        results = list(collection.aggregate(pipeline))

        sessions_list = []
        for r in results:
            sessions_list.append({
                "session_id": r["_id"],
                "collection_name": r.get("collection_name"),
                "created_at": r.get("created_at").isoformat() if r.get("created_at") else None,
                "last_activity": r.get("last_activity").isoformat() if r.get("last_activity") else None,
                "message_count": r.get("message_count", 0)
            })

        response = {
            "user_id": user_id,
            "total_sessions": len(sessions_list),
            "sessions": sessions_list
        }

        return jsonify(response), 200

    except Exception as e:
        app.logger.exception("Error listing RAG sessions")
        return jsonify({"error": str(e)}), 500

@app.route('/api/share-conversation', methods=['POST', 'OPTIONS'])
@login_required
def share_conversation():
    """
    Enable sharing for a conversation and return the shareable link.
    """
    # Handle OPTIONS preflight request
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json() or {}
        conversation_id = data.get('conversation_id')
        
        if not conversation_id:
            return jsonify({"error": "conversation_id is required"}), 400
        
        # Verify the conversation belongs to this user
        auth_user = session.get('user', {})
        user_id = auth_user.get('id') or auth_user.get('email')
        expected_prefix = f"conv_{user_id}_"
        
        if not conversation_id.startswith(expected_prefix):
            return jsonify({"error": "You can only share your own conversations"}), 403
        
        # Check if conversation exists
        conversation_exists = collection.find_one({"conversation_id": conversation_id})
        if not conversation_exists:
            return jsonify({"error": "Conversation not found"}), 404
        
        # Mark all messages in this conversation as shared
        result = collection.update_many(
            {"conversation_id": conversation_id},
            {"$set": {"is_shared": True, "shared_at": datetime.datetime.now(timezone.utc)}}
        )
        
        # Generate shareable link
        base_url = request.host_url.rstrip('/')
        share_link = f"{base_url}/shared/{conversation_id}"
        
        return jsonify({
            "success": True,
            "share_link": share_link,
            "conversation_id": conversation_id,
            "messages_updated": result.modified_count
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error enabling conversation sharing: {str(e)}")
        return jsonify({"error": "Failed to enable sharing"}), 500


@app.route('/api/unshare-conversation', methods=['POST', 'OPTIONS'])
@login_required
def unshare_conversation():
    """
    Disable sharing for a conversation.
    """
    # Handle OPTIONS preflight request
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json() or {}
        conversation_id = data.get('conversation_id')
        
        if not conversation_id:
            return jsonify({"error": "conversation_id is required"}), 400
        
        # Verify the conversation belongs to this user
        auth_user = session.get('user', {})
        user_id = auth_user.get('id') or auth_user.get('email')
        expected_prefix = f"conv_{user_id}_"
        
        if not conversation_id.startswith(expected_prefix):
            return jsonify({"error": "You can only unshare your own conversations"}), 403
        
        # Remove shared status from all messages in this conversation
        result = collection.update_many(
            {"conversation_id": conversation_id},
            {"$set": {"is_shared": False}, "$unset": {"shared_at": ""}}
        )
        
        return jsonify({
            "success": True,
            "conversation_id": conversation_id,
            "messages_updated": result.modified_count
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error disabling conversation sharing: {str(e)}")
        return jsonify({"error": "Failed to disable sharing"}), 500


@app.get('/shared/<conversation_id>')
def shared_conversation(conversation_id):
    """
    Retrieve and render a shared conversation by its conversation_id.
    Returns a rendered HTML template with the conversation details if found,
    otherwise returns an error message in JSON format.
    Only accessible if conversation has been explicitly shared.
    """
    try:
        # Fetch all messages for this conversation
        messages = list(collection.find(
            {"conversation_id": conversation_id}
        ).sort("timestamp", 1))
        
        if not messages:
            return jsonify({
                "error": "Conversation not found",
                "session_id": conversation_id
            }), 404
        
        # Check if conversation is shared (privacy control)
        is_shared = messages[0].get("is_shared", False)
        if not is_shared:
            return jsonify({
                "error": "This conversation is private and cannot be accessed",
                "message": "The owner has not shared this conversation"
            }), 403
        
        # Format response
        response = {
            "session_id": conversation_id,
            "collection_name": messages[0].get("collection_name"),
            "created_at": messages[0].get("timestamp").isoformat() if isinstance(messages[0].get("timestamp"), datetime) else (str(messages[0].get("timestamp")) if messages[0].get("timestamp") else None),
            "last_activity": messages[-1].get("timestamp").isoformat() if isinstance(messages[-1].get("timestamp"), datetime) else (str(messages[-1].get("timestamp")) if messages[-1].get("timestamp") else None),
            "message_count": len(messages),
            "messages": []
        }
        
        for msg in messages:
            response["messages"].append({
                "query": msg.get("query"),
                "answer": msg.get("answer"),
                "timestamp": msg.get("timestamp").isoformat() if isinstance(msg.get("timestamp"), datetime) else (str(msg.get("timestamp")) if msg.get("timestamp") else None),
                "model_used": msg.get("model_used"),
                "is_new_conversation": msg.get("is_new_conversation"),
                "role": msg.get("role")
            })
        
        # Return JSON for React frontend
        return jsonify(response), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching shared conversation: {str(e)}")
        return jsonify({"error": "Failed to fetch conversation"}), 500


# ==================== CONTACT EMAIL ENDPOINT ====================
@app.route('/api/send-contact-email', methods=['POST'])
def contact_email_endpoint():
    """
    Handle contact form submissions and send emails via SMTP.
    
    Expected JSON payload:
    {
        "sender_name": "John Doe",
        "sender_email": "john@example.com",
        "subject": "Inquiry about services",
        "message": "I would like to know more about...",
        "cc_emails": ["optional@example.com"],  // optional
        "bcc_emails": ["optional@example.com"]  // optional
    }
    
    Returns:
    - Success (200): {"status": "success", "message": "Email sent successfully"}
    - Validation Error (400): {"status": "error", "message": error_message}
    - Server Error (500): {"status": "error", "message": error_message}
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['sender_name', 'sender_email', 'subject', 'message']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                "status": "error",
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            }), 400
        
        # Extract optional fields
        cc_emails = data.get('cc_emails')
        bcc_emails = data.get('bcc_emails')
        recipient_email = data.get('recipient_email')  # Optional: override default
        
        # Validate that cc_emails and bcc_emails are lists if provided
        if cc_emails and not isinstance(cc_emails, list):
            return jsonify({
                "status": "error",
                "message": "cc_emails must be a list of email addresses"
            }), 400
        
        if bcc_emails and not isinstance(bcc_emails, list):
            return jsonify({
                "status": "error",
                "message": "bcc_emails must be a list of email addresses"
            }), 400
        
        # Send the email
        error_result = send_contact_email(
            sender_name=data['sender_name'],
            sender_email=data['sender_email'],
            subject=data['subject'],
            message=data['message'],
            recipient_email=recipient_email,
            cc_emails=cc_emails,
            bcc_emails=bcc_emails
        )
        
        # Check if there was an error
        if error_result:
            app.logger.warning(f"Contact email send failed: {error_result}")
            return jsonify({
                "status": "error",
                "message": error_result
            }), 400
        
        # Success
        app.logger.info(f"Contact email sent from {data['sender_name']} ({data['sender_email']})")
        return jsonify({
            "status": "success",
            "message": "Email sent successfully"
        }), 200
        
    except ValueError as e:
        app.logger.error(f"JSON parsing error in contact email: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Invalid JSON format"
        }), 400
    except Exception as e:
        app.logger.error(f"Unexpected error in contact email endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred while sending the email"
        }), 500

    
if __name__ == '__main__':
    # Create static folder if it doesn't exist
    app.run(host='0.0.0.0', port=5000)

