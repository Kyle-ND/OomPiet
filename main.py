import re
from datetime import timezone,timedelta,datetime
from bson import ObjectId
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, make_response, flash
from authlib.integrations.flask_client import OAuth
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
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

#Auth Utils
from Services.auth import utils as AuthUtils
from Services.auth.utils import login_required

from Services.auth import user_auth as UserAuth
from Services.payments import payment_auth as PayAuth

# Load environment variables
load_dotenv()

# Configuration
API_URL = os.getenv('API_URL')
API_KEY = os.getenv('API_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY')  # Default for development
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

# Start cleanup scheduler
# schedule_cleanup()
AuthUtils.schedule_cleanup() 

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
    return UserAuth.upload_user(UPLOAD_USERS)

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


# --- Modified Signup Endpoint ---
@app.route('/api/signup', methods=['POST'])
def signup():
    return UserAuth.handle_signup(users_collection, initialize_new_user_dashboard_stats)



@app.route('/api/signin', methods=['POST'])
def signin():
    return UserAuth.handle_signin(users_collection)




# Password Reset Endpoints
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    return UserAuth.handle_recover_password(users_collection)


@app.route('/reset-password/<token>')
def reset_password_page(token):
    """Display password reset form"""
    # Validate token
    token_data = AuthUtils.validate_reset_token(token) #validate_reset_token(token)
    if not token_data:
        return render_template('reset_password.html', error="Invalid or expired reset link")
    
    return render_template('reset_password.html', token=token, email=token_data['email'])


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    return UserAuth.handle_reset_password(users_collection)


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

@app.route('/logout', methods=['POST'])
def logout():
    user_email = session.get('user', {}).get('email')
    if user_email:
        #remove_user_session(user_email)
        AuthUtils.remove_user_session(user_email)
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
    return UserAuth.handle_feed_back(feedback_collection, dashboard_stats_collection)

@app.route('/api/invalidate-session', methods=['POST'])
def invalidate_session():
    """Invalidate current session (called when user logs in from another device)"""
    return UserAuth.handle_invalidate_session()

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
    return UserAuth.login(users_collection)

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
    # user = session.get('user')
    # if not user:
    #     return redirect(url_for('login'))

    # plan = request.args.get('plan', 'monthly')
    # amount = request.args.get('amount', '149.00')
    # recurring = request.args.get('recurring', 'false') == 'true'

    # if plan == 'annual':
    #     item_name = 'Premium Plan - Annual Subscription'
    #     recurring_amount = '1548.00'
    #     frequency = 6  # 6 = yearly in PayFast
    # else:
    #     item_name = 'Premium Plan - Monthly Subscription'
    #     recurring_amount = '149.00'
    #     frequency = 3  # 3 = monthly in PayFast

    # # Generate unique merchant reference for better tracking
    # merchant_ref = f"{user.get('email', '')}-{plan}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    # payfast_data = {
    #         'merchant_id': '25296103',
    #     'merchant_key': 'rbn0vhdzshrbi',
    #     'amount': amount,
    #     'item_name': item_name,
    #     'name_first': user.get('name', ''),
    #     'email_address': user.get('email', ''),
    #     'return_url': url_for('pay_success', _external=True),
    #     'cancel_url': url_for('pay_cancel', _external=True),
    #     'notify_url': url_for('pay_notify', _external=True),
    #     'custom_str1': user.get('email', ''),
    #     'custom_str2': plan,
    #     'custom_str3': merchant_ref,
    #     'm_payment_id': merchant_ref
    # }

    # if recurring:
    #     billing_date = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d')
    #     payfast_data.update({
    #         'subscription_type': 1,
    #         'billing_date': billing_date,
    #         'recurring_amount': recurring_amount,
    #         'frequency': frequency,
    #         'cycles': 0
    #     })
        
    #     app.logger.info(f"Creating recurring subscription for {user.get('email', '')}: {payfast_data}")
    #     print(f"Recurring subscription data: {payfast_data}")  # Terminal log

    # return render_template('payfast_form.html', payfast=payfast_data, recurring=recurring)
    return PayAuth.payment_op()

@app.route('/pay/success')
@login_required
def pay_success():
    # user = session.get('user')
    # if not user:
    #     return redirect(url_for('login'))
    
    # # Get plan from query parameters (in case it was passed back from PayFast)
    # plan = request.args.get('plan', 'monthly')
    
    # # Calculate subscription end date
    # if plan == 'annual':
    #     subscription_end = datetime.utcnow() + timedelta(days=365)
    #     plan_display = "annual"
    # else:
    #     subscription_end = datetime.utcnow() + timedelta(days=30)
    #     plan_display = "monthly"
    
    # # Mark user as premium in DB with subscription details
    # users_collection.update_one(
    #     {'email': user['email']}, 
    #     {'$set': {
    #         'premium': True,
    #         'subscription_plan': plan,
    #         'subscription_start': datetime.utcnow(),
    #         'subscription_end': subscription_end
    #     }}
    # )
    
    # # Update session
    # session['user']['premium'] = True
    # session['user']['subscription_plan'] = plan
    
    # # Show appropriate success message
    # if plan == 'annual':
    #     flash('Payment successful! You are now a premium user with an annual subscription.', 'success')
    # else:
    #     flash('Payment successful! You are now a premium user with a monthly subscription.', 'success')
    
    # return redirect(url_for('chat'))
    return PayAuth.payment_successful(users_collection)

@app.route('/pay/cancel')
@login_required
def pay_cancel():
    flash('Payment cancelled.', 'warning')
    return redirect(url_for('chat'))

@app.route('/pay/notify', methods=['POST'])
def pay_notify():
    # # Get the raw POST data from PayFast
    # raw_body = request.get_data(as_text=True)
    # received_signature = request.form.get('signature')

    # print("--- PayFast ITN Received ---")
    # app.logger.info("--- PayFast ITN Received ---")
    # print(f"Raw ITN Body: {raw_body}")
    # app.logger.info(f"Raw ITN Body: {raw_body}")
    # print(f"Received Signature: {received_signature}")
    # app.logger.info(f"Received Signature: {received_signature}")

    # # Find the start of the signature in the raw body
    # signature_part = "&signature="
    # signature_index = raw_body.rfind(signature_part)
    
    # # The string to hash is everything BEFORE the signature part
    # payload_to_hash = raw_body[:signature_index]
    
    # print(f"String to Hash (raw body minus signature): {payload_to_hash}")
    # app.logger.info(f"String to Hash (raw body minus signature): {payload_to_hash}")

    # # In sandbox, we hash the payload directly (no passphrase).
    # # In production, we append the passphrase.

    # if not PAYFAST_SANDBOX and PAYFAST_PASSPHRASE:
    #     string_to_check = f"{payload_to_hash}&passphrase={PAYFAST_PASSPHRASE}"
    # else:
    #     string_to_check = payload_to_hash

    # print(f"Final String for Hashing: {string_to_check}")
    # app.logger.info(f"Final String for Hashing: {string_to_check}")

    # calculated_signature = hashlib.md5(string_to_check.encode('utf-8')).hexdigest()
    
    # print(f"Calculated Signature: {calculated_signature}")
    # app.logger.info(f"Calculated Signature: {calculated_signature}")

    # # --- Verification ---
    # if calculated_signature != received_signature:
    #     print("!!! SIGNATURE MISMATCH !!!")
    #     app.logger.error("!!! PayFast ITN Signature Mismatch !!!")
    #     return "Invalid signature", 400

    # print("--- SIGNATURE VERIFIED ---")
    # app.logger.info("--- PayFast ITN Signature Verified ---")

    # # --- Process Payment ---
    # # Use request.form to get the decoded data for processing
    # data = dict(request.form)
    # payment_status = data.get('payment_status')
    # email = data.get('custom_str1')
    # plan = data.get('custom_str2', 'monthly')
    
    # if payment_status == 'COMPLETE' and email:
    #     pf_subscription_id = (
    #         data.get('pf_subscription_id') or 
    #         data.get('subscription_id') or 
    #         data.get('recurring_transaction_id') or 
    #         data.get('m_payment_id') or 
    #         ''
    #     )
        
    #     app.logger.info(f"Processing COMPLETE payment for {email}, subscription_id: {pf_subscription_id}")
    #     print(f"Processing COMPLETE payment for {email}, subscription_id: {pf_subscription_id}")
        
    #     if plan == 'annual':
    #         subscription_end = datetime.utcnow() + timedelta(days=365)
    #     else:
    #         subscription_end = datetime.utcnow() + timedelta(days=30)
        
    #     update_fields = {
    #         'premium': True,
    #         'subscription_plan': plan,
    #         'subscription_start': datetime.utcnow(),
    #         'subscription_end': subscription_end,
    #         'payment_amount': data.get('amount_gross', '0.00'), # Use amount_gross from ITN
    #         'payment_id': data.get('pf_payment_id', ''),
    #         'payfast_subscription_id': pf_subscription_id,
    #         'last_payment_date': datetime.utcnow()
    #     }
        
    #     users_collection.update_one({'email': email}, {'$set': update_fields})
    #     app.logger.info(f"User {email} upgraded to premium with {plan} plan")
        
    # else:
    #     app.logger.warning(f"Payment status '{payment_status}' for user {email}. No action taken.")
    #     print(f"Payment status '{payment_status}' for user {email}. No action taken.")
    
    # return 'OK', 200
    return PayAuth.payment_notification(users_collection, PAYFAST_SANDBOX, PAYFAST_PASSPHRASE)

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


if __name__ == '__main__':
    # Create static folder if it doesn't exist
    
    app.run(host='0.0.0.0', port=5000, debug=True)