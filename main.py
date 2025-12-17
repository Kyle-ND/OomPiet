from datetime import timezone,timedelta,datetime
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
import msal
import re
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
import json
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Load environment variables
load_dotenv()
#Auth Utils
from Services.auth import utils as AuthUtils
from Services.auth.utils import login_required
from Services.auth import user_auth as UserAuth
from Services.payments import payment_auth as PayAuth

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

# CRITICAL: CORS configuration for cross-origin requests from Vercel
# Safari requires exact origin matching - no wildcard patterns
CORS(app, 
    origins = [
    "https://mentormate-client.vercel.app",
    "http://localhost:3000",
    "https://mentormate.co.za",   
    "https://www.mentormate.co.za",   
    ],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept'],
     methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
     expose_headers=['Set-Cookie'],
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
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Required for cross-site cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Required for production HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_DOMAIN'] = None  # Let browser handle domain
# CRITICAL FIX: Removed PARTITIONED - conflicts with SameSite=None in Safari
# Partitioned is for Chrome Privacy Sandbox, breaks Safari compatibility

# Initialize Flask-Session (server-side sessions)
Session(app)

app.logger.setLevel(logging.INFO)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
db = client["geotech_db"]
users_collection = db["users"]
dashboard_stats_collection = db["dashboard_stats"]
feedback_collection = db["feedback"]
sessions_collection = db["sessions"]
password_reset_collection = db["password_reset_tokens"]
collection = db["rag_queries"]

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
    server_metadata_url=f'https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/v2.0/.well-known/openid-configuration',
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

app.json_encoder = JSONEncoder

# Start cleanup scheduler
# schedule_cleanup()
AuthUtils.schedule_cleanup() 


def _content_security_policy():

    return (
        "default-src 'self'; "
        "script-src 'self' https://accounts.google.com https://www.gstatic.com https://www.googleapis.com 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://accounts.google.com https://www.googleapis.com https://oompiet.space/rag https://mentormate-client.vercel.app/; "
        "frame-src https://accounts.google.com;"
    )

@app.after_request
def add_security_headers(response):
    # Prevent MIME type sniffing
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # Prevent clickjacking
    response.headers.setdefault('X-Frame-Options', 'DENY')
    # Referrer policy
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    # XSS protection (legacy, still useful for some older user agents)
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')
    # Permissions policy — disable sensitive features by default
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    # Content Security Policy
    response.headers.setdefault('Content-Security-Policy', _content_security_policy())

    # HSTS only in production (requires HTTPS)
    if MODE == 'production':
        response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
        # Ensure cookies marked secure in production
        app.config['SESSION_COOKIE_SECURE'] = True

    return response

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


limiter = Limiter(
    app=app,
    key_func = get_remote_address,
)

@app.route('/upload-login', methods=['POST'])
def upload_login():
    return UserAuth.handle_upload_user(UPLOAD_USERS)

def initialize_new_user_dashboard_stats(email):
    stats = {
        "user_email": email,
        "total_chats": 0,
        "total_messages": 0,
        "last_active": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc)
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
@limiter.limit("3 per minute",  key_func= get_remote_address)
def signup():
    return UserAuth.handle_signup(users_collection, initialize_new_user_dashboard_stats)



@app.route('/api/check-session', methods=['GET'])
def check_session():
    """Check if user has active session"""
    # CRITICAL FIX: Handle multiple cookies with same name
    # Browser may send multiple 'google-login-session' cookies
    # We need to try ALL of them, not just the first one Flask loads
    cookie_header = request.headers.get('Cookie', '')
    cookie_name = app.config['SESSION_COOKIE_NAME']
    
    # Extract all cookies with our session name
    import re
    pattern = rf'{cookie_name}=([^;]+)'
    all_session_cookies = re.findall(pattern, cookie_header)
    
    is_authenticated = 'user' in session
    user_data = session.get('user', None)
    
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
                        import pickle
                        session_data = pickle.loads(found_session['val'])
                        
                        if 'user' in session_data:
                            is_authenticated = True
                            user_data = session_data['user']
                            break
                        
            except Exception as e:
                app.logger.error(f"Error checking alternate cookies: {e}")
    
    response_data = {
        'authenticated': is_authenticated,
        'user': user_data
    }
    
    return jsonify(response_data), 200


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
@app.route('/login/google')  # Add explicit Google login route
# @limiter.limit("5 per minute")
def login():
    # CRITICAL: Must regenerate session to avoid duplicate cookie issue
    # Get old session ID BEFORE clearing (clearing generates new ID)
    old_cookie = request.cookies.get(app.config['SESSION_COOKIE_NAME'], '')
    old_sid = old_cookie.split('.')[0] if old_cookie else None
    
    # Delete ALL old sessions from MongoDB to prevent accumulation
    if old_sid:
        try:
            session_collection = client['geotech_db']['flask_sessions']
            existing = session_collection.find_one({"id": old_sid})
            if existing:
                session_collection.delete_one({"id": old_sid})
        except Exception as e:
            app.logger.warning(f"Could not delete old session: {e}")
    
    # NOW clear the session (this generates a NEW session ID)
    session.clear()
    # Set redirect URL for callback
    session['redirect_url'] = "https://mentormate-client.vercel.app/google-callback"
    
    redirect_uri = url_for('google_callback', _external=True)
    
    # Let Authlib automatically generate and store state in session
    response = google.authorize_redirect(redirect_uri=redirect_uri)
    
    # CRITICAL FIX: Manually save session to MongoDB with proper write concern
    # Flask-Session's save_session() doesn't guarantee immediate persistence
    session.modified = True
    try:
        # Call save_session first (sets cookie in response)
        app.session_interface.save_session(app, session, response)
        
        # FORCE immediate MongoDB write with acknowledgment
        cookie_header = response.headers.get('Set-Cookie', '')
        if 'google-login-session=' in cookie_header:
            cookie_value = cookie_header.split('google-login-session=')[1].split(';')[0]
            session_id = cookie_value.split('.')[0] if '.' in cookie_value else cookie_value
            
            # Manually insert/update with write concern to FORCE persistence
            session_collection = client['geotech_db']['flask_sessions']
            import pickle
            
            session_doc = {
                'id': session_id,
                'val': pickle.dumps(dict(session)),
                'expiration': datetime.utcnow() + timedelta(minutes=60)
            }
            
            # Use replace_one with upsert to ensure write completes
            result = session_collection.replace_one(
                {'id': session_id},
                session_doc,
                upsert=True
            )
            
            # Verify write succeeded
            if not result.acknowledged:
                app.logger.error(f"MongoDB write NOT acknowledged for session {session_id[:20]}...")
            
    except Exception as e:
        app.logger.error(f"Session save failed: {type(e).__name__}: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        # Don't crash - continue with redirect, recovery function will handle it
    
    return response

@app.route('/login/microsoft')
def microsoft_login():
    """Initiate Microsoft OAuth login"""
    # CRITICAL: Must regenerate session to avoid duplicate cookie issue
    # Get old session ID BEFORE clearing (clearing generates new ID)
    old_cookie = request.cookies.get(app.config['SESSION_COOKIE_NAME'], '')
    old_sid = old_cookie.split('.')[0] if old_cookie else None
    
    # Delete ALL old sessions from MongoDB to prevent accumulation
    if old_sid:
        try:
            session_collection = client['geotech_db']['flask_sessions']
            existing = session_collection.find_one({"id": old_sid})
            if existing:
                session_collection.delete_one({"id": old_sid})
        except Exception as e:
            app.logger.warning(f"Could not delete old session: {e}")
    
    # NOW clear the session (this generates a NEW session ID)
    session.clear()
    
    # Set redirect URL for callback
    session['redirect_url'] = "https://mentormate-client.vercel.app/microsoft-callback"
    
    # Generate authorization URL - let Authlib handle state automatically
    redirect_uri = url_for('microsoft_callback', _external=True)
    response = microsoft.authorize_redirect(redirect_uri)
    
    # CRITICAL FIX: Manually save session to MongoDB with proper write concern
    # Flask-Session's save_session() doesn't guarantee immediate persistence
    session.modified = True
    try:
        # Call save_session first (sets cookie in response)
        app.session_interface.save_session(app, session, response)
        
        # FORCE immediate MongoDB write with acknowledgment
        cookie_header = response.headers.get('Set-Cookie', '')
        if 'google-login-session=' in cookie_header:
            cookie_value = cookie_header.split('google-login-session=')[1].split(';')[0]
            session_id = cookie_value.split('.')[0] if '.' in cookie_value else cookie_value
            
            # Manually insert/update with write concern to FORCE persistence
            session_collection = client['geotech_db']['flask_sessions']
            import pickle
            
            session_doc = {
                'id': session_id,
                'val': pickle.dumps(dict(session)),
                'expiration': datetime.utcnow() + timedelta(minutes=60)
            }
            
            # Use replace_one with upsert to ensure write completes
            result = session_collection.replace_one(
                {'id': session_id},
                session_doc,
                upsert=True
            )
            
            # Verify write succeeded
            if not result.acknowledged:
                app.logger.error(f"MongoDB write NOT acknowledged for session {session_id[:20]}...")
            
    except Exception as e:
        app.logger.error(f"Session save failed: {type(e).__name__}: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        # Don't crash - continue with redirect, recovery function will handle it
    
    return response

@app.route('/microsoft/callback')
def microsoft_callback():
    """Handle Microsoft OAuth callback"""
    return UserAuth.handle_microsoft_callback(microsoft, users_collection, initialize_new_user_dashboard_stats)


@app.route('/google/callback')
def google_callback():
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
        response = redirect("https://mentormate-client.vercel.app/mentormate-homepage")
    
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

@app.route('/api/clear-all-sessions', methods=['POST'])
def clear_all_sessions():
    """Clear all sessions from MongoDB - useful for testing clean state"""
    try:
        session_collection = client['geotech_db']['flask_sessions']
        result = session_collection.delete_many({})
        
        # Also clear current session
        session.clear()
        
        response = jsonify({
            "success": True,
            "message": f"Cleared {result.deleted_count} sessions from MongoDB",
            "deleted_count": result.deleted_count
        })
        
        # Delete cookie
        response.set_cookie(
            app.config['SESSION_COOKIE_NAME'],
            value='',
            max_age=0,
            secure=True,
            httponly=True,
            samesite='None',
            path='/'
        )
        
        app.logger.info(f"Cleared {result.deleted_count} sessions from MongoDB")
        return response, 200
        
    except Exception as e:
        app.logger.error(f"Error clearing sessions: {e}")
        return jsonify({"error": str(e)}), 500

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
    return redirect("https://mentormate-client.vercel.app/payment-cancelled")

@app.route('/pay/notify', methods=['POST'])
def pay_notify():
    return PayAuth.payment_notification(users_collection, PAYFAST_SANDBOX, PAYFAST_PASSPHRASE)

@app.route('/unsubscribe', methods=['POST'])
@login_required
def unsubscribe():
    return UserAuth.handle_unsubscription(users_collection, PAYFAST_SANDBOX)


@app.route("/chat_history/<user_id>", methods=["GET"])
def get_history_chat(user_id):
    
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
                    "timestamp": msg.get("timestamp").isoformat() if isinstance(msg.get("timestamp"), datetime) else (str(msg.get("timestamp")) if msg.get("timestamp") else None),
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
def get_specific_session(user_id, conversation_id):
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
            "created_at": messages[0].get("timestamp").isoformat() if isinstance(messages[0].get("timestamp"), datetime) else (str(messages[0].get("timestamp")) if messages[0].get("timestamp") else None),
            "last_activity": messages[-1].get("timestamp").isoformat() if isinstance(messages[-1].get("timestamp"), datetime) else (str(messages[-1].get("timestamp")) if messages[-1].get("timestamp") else None),
            "message_count": len(messages),
            "messages": []
        }
        
        for msg in messages:
            message_data = {
                "query": msg.get("query"),
                "answer": msg.get("answer"),
                "timestamp": msg.get("timestamp").isoformat() if isinstance(msg.get("timestamp"), datetime) else (str(msg.get("timestamp")) if msg.get("timestamp") else None),
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
def delete_chat_history(user_id):
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
        now = datetime.now(timezone.utc)
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
                    "timestamp": datetime.now(timezone.utc),
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
            {"$set": {"is_shared": True, "shared_at": datetime.now(timezone.utc)}}
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
    


if __name__ == '__main__':
    # Create static folder if it doesn't exist
    app.run(host='0.0.0.0', port=5000)
