from datetime import timezone,timedelta,datetime
from bson import ObjectId
from flask import Flask, jsonify, redirect, request, url_for, session, send_from_directory
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

# PayFast Configuration
PAYFAST_MERCHANT_ID = os.getenv('PAYFAST_MERCHANT_ID')
PAYFAST_MERCHANT_KEY = os.getenv('PAYFAST_MERCHANT_KEY')
PAYFAST_PASSPHRASE = os.getenv('PAYFAST_PASSPHRASE', '')
PAYFAST_SANDBOX = os.getenv('PAYFAST_SANDBOX', 'true').lower() == 'true'

app = Flask(__name__, static_folder='static')

CORS(app, 
     origins=["http://localhost:3000"],  # Specific origins for credentials
     methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     expose_headers=["Content-Type", "Authorization"],
     supports_credentials=True,  # Enable credentials with specific origins
     max_age=3600
)



app.secret_key = SECRET_KEY

# Configure server-side sessions with filesystem (simple, no MongoDB compatibility issues)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(__file__), 'flask_session')
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_USE_SIGNER'] = True  # Sign the session ID cookie
# For development: Share cookies across localhost ports by setting domain to 'localhost'
# This allows localhost:3000 and localhost:5000 to share the same session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Lax allows same-site requests
app.config['SESSION_COOKIE_SECURE'] = False  # False for http://localhost (use True in production with HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_DOMAIN'] = 'localhost'  # Share across all localhost ports

# Initialize Flask-Session (server-side sessions)
Session(app)

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
collection = db["rag_queries"]
doc = {
  "conversation_id": "conv_test-user-1234",
  "collection_name": "Concrete_docs",
  "timestamp": datetime.now(timezone.utc),
  "query": "hello",
  "answer": "hi",
  "model_used": "test-model",
  "is_new_conversation": True,
  "role": "assistant"
}
res = db['rag_queries'].insert_one(doc)
print(res.inserted_id)




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
    client_id=TENANT_ID,
    client_secret=CLIENT_SECRET,  
    authorize_url=f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize',
    authorize_params=None,
    access_token_url=f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='YOUR_CALLBACK_URL',  # e.g., 'http://localhost:5000/auth/microsoft/callback'
    client_kwargs={
        'scope': 'openid email profile User.Read',
        'token_endpoint_auth_method': 'client_secret_post',
    },
    server_metadata_url=f'https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration',
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
        "connect-src 'self' https://accounts.google.com https://www.googleapis.com https://oompiet.space/rag; "
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
    return UserAuth.upload_user(UPLOAD_USERS)

# Routes - Templates removed, using React frontend



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
    is_authenticated = 'user' in session
    return jsonify({
        'authenticated': is_authenticated,
        'user': session.get('user', None) if is_authenticated else None
    }), 200


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
    session.clear()

    # Redirect to frontend callback page after login
    session['redirect_url'] = "http://localhost:3000/google-callback"

    session['oauth_state'] = os.urandom(16).hex()
    session.modified = True
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(
        redirect_uri=redirect_uri,
        state=session['oauth_state']
    )

@app.route('/login/microsoft')
def microsoft_login():
    """Initiate Microsoft OAuth login"""
    session.clear()
    
    # Redirect to frontend callback page after login
    session['redirect_url'] = "http://localhost:3000/microsoft-callback"

    # Generate and store state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Generate authorization URL
    redirect_uri = url_for('microsoft_callback', _external=True)
    return microsoft.authorize_redirect(redirect_uri, state=state)

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
        #remove_user_session(user_email)
        AuthUtils.remove_user_session(user_email)
    session.pop('upload_access', None)
    session.clear()
    
    # Check if request expects JSON or redirect
    if request.method == 'POST' or request.headers.get('Content-Type') == 'application/json':
        return jsonify({"success": True, "message": "Logged out successfully"})
    else:
        # Redirect to frontend homepage (same as login redirect)
        return redirect("http://localhost:3000/mentormate-homepage")

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
    return redirect("http://localhost:3000/payment-cancelled")

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
        debug_mode = request.args.get('debug', 'false').lower() == 'true'

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
    # TEMPORARY: Auth disabled for development due to cross-origin cookie issues
    # TODO: Implement token-based auth for production
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
        is_new = False
        if not conversation_id:
            conversation_id = f"conv_{user_id}_{uuid.uuid4().hex[:8]}"
            is_new = True
        else:
            # Validate conversation_id format and ownership
            # If conversation_id doesn't belong to this user, regenerate it
            expected_prefix = f"conv_{user_id}_"
            if not str(conversation_id).startswith(expected_prefix):
                # Regenerate conversation_id for this user instead of rejecting
                conversation_id = f"conv_{user_id}_{uuid.uuid4().hex[:8]}"
                is_new = True

        # Basic validation
        if not query_text:
            return jsonify({"error": "query is required"}), 400

        # Forward to external RAG service (configurable via RAG_SERVICE_URL)
        rag_url = os.getenv('RAG_SERVICE_URL') or 'https://oompiet.space/rag'
        forward_payload = data.copy()
        forward_payload['conversation_id'] = conversation_id
        forward_payload['user_id'] = user_id
        
        # Log payload for debugging
        app.logger.info(f"RAG Request - collection_name: {collection_name}, conversation_id: {conversation_id}, query: {query_text[:50] if query_text else None}")

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
        print(f"Error in /api/rag proxy: {str(e)}")
        import traceback
        traceback.print_exc()
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


if __name__ == '__main__':
    # Create static folder if it doesn't exist
    app.run(host='0.0.0.0', port=5000,debug = True)