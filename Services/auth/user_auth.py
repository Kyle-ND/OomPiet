import os
import re
import pickle
import uuid
from urllib.parse import urlencode
from flask import current_app, make_response, redirect, request, jsonify , session, url_for
from datetime import datetime, timedelta, timezone
import requests
from werkzeug.security import check_password_hash,generate_password_hash
from Utils.EmailSender import send_password_reset_email
from . import utils as AuthUtils

TENANT_ID = os.getenv("TID")  
CLIENT_ID = os.getenv("CID")  
CLIENT_SECRET = os.getenv("SID")  

def add_partitioned_to_response(response):
    """Add Partitioned attribute to session cookies for Safari/Brave"""
    cookies = response.headers.getlist('Set-Cookie')
    if not cookies:
        return response
    
    response.headers.remove('Set-Cookie')
    session_cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
    
    for cookie in cookies:
        if session_cookie_name in cookie and 'Partitioned' not in cookie:
            cookie = cookie.rstrip(';').rstrip() + '; Partitioned'
            current_app.logger.info(f"✓ Added Partitioned to cookie")
        response.headers.add('Set-Cookie', cookie)
    
    return response


def recover_oauth_session_from_cookies(provider_name, state_in_url):
    """
    Safely recover OAuth session when Flask loads wrong cookie from multiple cookies.
    
    Security measures:
    - Only loads OAuth state data (not full session)
    - Validates session timestamp (must be recent)
    - Validates IP address matches (optional, can be disabled for mobile users)
    - Limits number of cookies checked (prevents DoS)
    
    Args:
        provider_name: 'google' or 'microsoft'
        state_in_url: OAuth state parameter from callback URL
        
    Returns:
        bool: True if session was recovered, False otherwise
    """
    state_key = f'_state_{provider_name}_{state_in_url}' if state_in_url else None
    
    if not state_key or state_key in session:
        return False  # Already have state or no state to find
    
    current_app.logger.warning(f"State {state_key} not in current session, attempting recovery...")
    
    # Get cookie name from config
    cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
    
    # Parse all session cookies from Cookie header
    cookie_header = request.headers.get('Cookie', '')
    all_cookies = re.findall(rf'{re.escape(cookie_name)}=([^;]+)', cookie_header)
    
    current_app.logger.info(f"Found {len(all_cookies)} {cookie_name} cookies")
    
    if len(all_cookies) <= 1:
        return False  # No alternate cookies to try
    
    # Limit to 5 cookies max to prevent DoS
    cookies_to_check = all_cookies[:5]
    
    # Get MongoDB configuration
    mongo_client = current_app.config.get('SESSION_MONGODB')
    db_name = current_app.config.get('SESSION_MONGODB_DB', 'geotech_db')
    collection_name = current_app.config.get('SESSION_MONGODB_COLLECT', 'flask_sessions')
    
    if not mongo_client:
        current_app.logger.error("SESSION_MONGODB not configured")
        return False
    
    session_collection = mongo_client[db_name][collection_name]
    
    # Extract cookie IDs safely
    cookie_ids = []
    for cookie_value in cookies_to_check:
        parts = cookie_value.split('.')
        if len(parts) >= 1:
            cookie_ids.append(parts[0])
    
    if not cookie_ids:
        current_app.logger.warning("No valid cookie IDs found")
        return False
    
    current_app.logger.info(f"Extracted cookie IDs: {[cid[:20] + '...' for cid in cookie_ids]}")
    
    # Batch query for all cookies at once (performance optimization)
    found_sessions = list(session_collection.find({"id": {"$in": cookie_ids}}))
    current_app.logger.info(f"MongoDB found {len(found_sessions)} sessions for {len(cookie_ids)} cookies")
    
    request_ip = request.remote_addr
    current_time = datetime.now(timezone.utc)
    
    for found_session in found_sessions:
        cookie_id = found_session.get('id')
        current_app.logger.info(f"Checking session {cookie_id[:20]}...")
        
        try:
            # Deserialize session data
            # Note: Flask-Session uses pickle. For production, consider migrating to JSON-based sessions
            session_data = pickle.loads(found_session['val'])
            current_app.logger.info(f"  Deserialized successfully. Keys: {list(session_data.keys())}")
            
            # Check if this session has the state we're looking for
            if state_key not in session_data:
                current_app.logger.info(f"  State key {state_key} not found in session")
                continue
            
            current_app.logger.info(f"Found state in session {cookie_id[:20]}...")
            
            # SECURITY: Validate session timestamp (must be within last 10 minutes)
            state_data = session_data.get(state_key, {})
            state_exp = state_data.get('exp')
            
            if state_exp:
                state_created = datetime.fromtimestamp(state_exp - 600, tz=timezone.utc)  # exp is 10 min from creation
                age_minutes = (current_time - state_created).total_seconds() / 60
                current_app.logger.info(f"  Session age: {age_minutes:.1f} minutes")
                
                if age_minutes > 10:
                    current_app.logger.warning(f"  Session too old ({age_minutes:.1f} minutes), skipping")
                    continue
            
            # SECURITY: Optionally validate IP address
            # Disabled by default as mobile users may have changing IPs during OAuth flow
            # session_ip = session_data.get('ip_address')
            # if session_ip and session_ip != request_ip:
            #     current_app.logger.warning(f"IP mismatch: session={session_ip}, request={request_ip}")
            #     continue
            
            # Only copy OAuth state keys (not user data or other session keys)
            # This prevents session fixation attacks
            oauth_keys = [k for k in session_data.keys() if k.startswith('_state_') or k == 'redirect_url']
            
            current_app.logger.info(f"✓ Validated session! Loading {len(oauth_keys)} OAuth keys...")
            
            for key in oauth_keys:
                session[key] = session_data[key]
            
            session.modified = True
            return True
            
        except Exception as e:
            current_app.logger.error(f"Failed to deserialize/validate session {cookie_id[:20]}: {type(e).__name__}: {e}")
            continue
    
    current_app.logger.warning("Could not recover OAuth state from any alternate cookie")
    return False


def handle_signup(users_collection , initialize_new_user_dashboard_stats_func):
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        first_name = data.get('firstName', '').strip()
        last_name = data.get('lastName', '').strip()
        birthdate = data.get('birthdate', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # if not is_valid_email(email): 
        if not AuthUtils.is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'}),400

        # Check if user already exists
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return jsonify({'success': False, 'error': 'An account with this email already exists'}), 400

        # Hash password and create user (verified immediately since no OTP flow)
        hashed_password = generate_password_hash(password)
        user_data = {
            'email': email,
            'password': hashed_password,
            'name': f"{first_name} {last_name}",
            'surname': last_name,
            'birthdate': birthdate,
            'phone': phone,
            'picture': '/static/avatardefault.png',
            'auth_method': 'email',
            'created_at': datetime.now(timezone.utc),
            'last_login': datetime.now(timezone.utc),
            'verified': True
        }
        users_collection.insert_one(user_data)
        initialize_new_user_dashboard_stats_func(email)

        # Automatically log the user in after successful signup
        session.permanent = True
        session['user'] = {
            'email': email,
            'name': f"{first_name} {last_name}",
            'picture': '/static/avatardefault.png',
            'auth_method': 'email',
            'premium': False
        }
        session['session_id'] = AuthUtils.create_user_session(email)

        current_app.logger.info(f"Signup and auto-login successful for user: {email}")
        return jsonify({'success': True, 'message': 'Account created successfully!', 'user': session['user']}), 200

    except Exception as e:
        current_app.logger.error(f"Error in signup: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during registration'}), 500
    

def handle_signin(users_collection):
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

        # Clean up expired sessions and remove any active session
        AuthUtils.cleanup_user_expired_sessions(email)
        active_session = AuthUtils.get_active_session_info(email)
        if active_session:
            AuthUtils.remove_user_session(email)

        # If no session conflict, continue with successful login
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user.get('name', ''),
            'picture': user.get('picture', '/static/default-profile.png'),
            'auth_method': user.get('auth_method', 'email'),
            'premium': user.get('premium', False)
        }
        session['session_id'] = AuthUtils.create_user_session(email)

        current_app.logger.info(f"Login successful for user: {email}")
        return jsonify({'success': True, 'message': 'Login successful', 'user': session['user']}), 200

    except Exception as e:
        current_app.logger.error(f"Signin error: {str(e)}")
        return jsonify({'success': False, 'error': f'An internal server error occurred: {str(e)}'}), 500




    

def handle_recover_password(users_collection,email):
    try:
        # Validation
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # if not is_valid_email(email):
        if not AuthUtils.is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        

        print("Checking if user exists...")
        
        # Check if user exists and uses email authentication
        user = users_collection.find_one({'email': email})

        if not user:
            # Don't reveal if user exists or not for security
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        
        # Only allow password reset for email-authenticated users
        if user.get('auth_method') != 'email':
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        
        # Generate reset token
        reset_token = AuthUtils.create_password_reset_token(email) #create_password_reset_token(email)

        if not reset_token:
            return jsonify({'success': False, 'error': 'Failed to generate reset token'}), 500
        
        # Create reset link
        reset_link = url_for('reset_password_page', token=reset_token, _external=True)

        # Log the reset link being generated
        current_app.logger.info(f"Generated reset link: {reset_link}")
        
        # Send email using the new EmailSender package
        error_message = send_password_reset_email(email, reset_link)

        # Log what the email sender returned
        current_app.logger.info(f"Email sender returned: {error_message if error_message else 'SUCCESS'}")
        
        if error_message is None:
            current_app.logger.info(f"Password reset email sent to: {email}")
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        else:
            current_app.logger.error(f"Failed to send password reset email: {error_message}")
            return jsonify({'success': False, 'error': 'Failed to send password reset email. Please try again later.'}), 500
          
        
    except Exception as e:
        current_app.logger.error(f"Error in forgot_password: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while processing your request'}), 500
    

def handle_upload_user(UPLOAD_USERS):
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


def handle_login(users_collection):
    try:
        data = request.get_json()
        user_email = data.get('email')
        
        if not user_email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # Remove all existing sessions for this user
        AuthUtils.remove_user_session(user_email)
        
        # Get user data
        user = users_collection.find_one({'email': user_email})
        if not user:
            current_app.logger.error(f"Force login failed: User not found for email: {user_email}")
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        current_app.logger.info(f"User found: {user.get('name', 'Unknown')}")
        
        # Create new session
        current_app.logger.info("Creating new session")
        session_id = AuthUtils.create_user_session(user_email) #create_user_session(user_email)
        
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
        
        return jsonify({
            'success': True,
            'user': session['user']
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in force login: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during force login'}), 500
    

def handle_feed_back(feedback_collection, dashboard_stats_collection):
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
            "timestamp": datetime.now(timezone.utc),
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
                "$set": {"last_active": datetime.now(timezone.utc)}
            }
        )
        
        return jsonify({"success": True, "message": "Feedback submitted successfully"})
        
    except Exception as e:
        current_app.logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    

def handle_reset_password(users_collection):
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
        token_data = AuthUtils.validate_reset_token(token) #validate_reset_token(token)
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
            {'$set': {'password': hashed_password, 'last_login': datetime.now(timezone.utc)}}
        )
        
        # Mark token as used
        # mark_token_as_used(token)
        AuthUtils.mark_token_as_used(token)
        
        # Remove all active sessions for this user (force re-login)
        # remove_user_session(token_data['email'])
        AuthUtils.remove_user_session(token_data['email'])
        
        current_app.logger.info(f"Password reset successful for: {token_data['email']}")
        return jsonify({'success': True, 'message': 'Password reset successful! You can now sign in with your new password.'})
        
    except Exception as e:
        current_app.logger.error(f"Error in reset_password: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while resetting your password'}), 500
    
def handle_microsoft_callback(microsoft, users_collection, initialize_new_user_dashboard_stats):
    """
    UPDATED: Microsoft OAuth callback with Partitioned cookie support
    """
    current_app.logger.info("=== MICROSOFT CALLBACK START ===")
    current_app.logger.info(f"Request cookies: {list(request.cookies.keys())}")
    
    state_in_url = request.args.get('state')
    current_app.logger.info(f"State in URL: {state_in_url}")
    
    # Attempt to recover OAuth session
    recover_oauth_session_from_cookies('microsoft', state_in_url)
    
    redirect_url = session.get('redirect_url', "https://mentormate-client.vercel.app/microsoft-callback")
    
    try:
        current_app.logger.info("Calling authorize_access_token()...")
        token = microsoft.authorize_access_token()
        current_app.logger.info(f"Token received: {token is not None}")
        
        if not token:
            raise ValueError("Failed to get access token")

        resp = microsoft.get('https://graph.microsoft.com/v1.0/me', token=token)
        user_info = resp.json()
        
        if not user_info or 'mail' not in user_info and 'userPrincipalName' not in user_info:
            raise ValueError("Failed to get user info from Microsoft")

        user_email = user_info.get('mail') or user_info.get('userPrincipalName')
        
        if not user_email:
            raise ValueError("No email found in user info")

        # Check and remove existing session
        active_session = AuthUtils.get_active_session_info(user_email)
        if active_session:
            AuthUtils.remove_user_session(user_email)
        
        # Fetch profile picture
        profile_picture = get_microsoft_profile_picture(microsoft, token)

        user_data = {
            "name": user_info.get("displayName", "User"),
            "email": user_email,
            "picture": profile_picture,
            "last_login": datetime.now(timezone.utc),
            "auth_method": "microsoft"
        }

        result = users_collection.update_one(
            {"email": user_data["email"]},
            {"$set": user_data},
            upsert=True
        )

        if result.upserted_id:
            initialize_new_user_dashboard_stats(user_data["email"])

        db_user = users_collection.find_one({"email": user_data["email"]})

        # Clear old session
        session.clear()
        
        # Create new session
        session_id = AuthUtils.create_user_session(user_data["email"])

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
        
        current_app.logger.info(f"Microsoft OAuth: Session created for {db_user['email']}")
        
        # Create redirect with session token
        session_token = session.sid if hasattr(session, 'sid') else str(uuid.uuid4())
        
        params = {
            "email": db_user["email"],
            "name": db_user["name"],
            "picture": db_user.get("picture", "/static/default-profile.png"),
            "session_token": session_token
        }
        
        from urllib.parse import urlencode
        final_redirect = f"{redirect_url}?{urlencode(params)}"
        
        # Create response
        current_app.logger.info(f"Microsoft OAuth: Using 302 redirect")
        response = make_response(redirect(final_redirect, code=302))
        
        # Force session save
        session.modified = True
        session.permanent = True
        current_app.session_interface.save_session(current_app, session, response)
        
        # NEW: Add Partitioned attribute
        response = add_partitioned_to_response(response)
        
        # Log cookie headers
        set_cookie_headers = response.headers.getlist('Set-Cookie')
        current_app.logger.info(f"📤 Response Set-Cookie headers: {len(set_cookie_headers)}")
        
        for idx, cookie in enumerate(set_cookie_headers):
            current_app.logger.info(f"   [{idx}] {cookie[:200]}")
            if 'Partitioned' in cookie:
                current_app.logger.info("   ✓ Has Partitioned attribute")
        
        current_app.logger.info(f"Redirecting to {final_redirect[:100]}...")
        return response

    except Exception as e:
        current_app.logger.error(f"Error in Microsoft callback: {str(e)}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        session.clear()
        return redirect(f"{redirect_url}?error=auth_failed&message={str(e)}")
    

# def handle_microsoft_callback(microsoft, users_collection, initialize_new_user_dashboard_stats):
#     current_app.logger.info("=== MICROSOFT CALLBACK START ===")
#     current_app.logger.info(f"Request cookies: {list(request.cookies.keys())}")
#     current_app.logger.info(f"Session contains user: {'user' in session}")
    
#     state_in_url = request.args.get('state')
#     current_app.logger.info(f"State in URL: {state_in_url}")
    
#     # Attempt to recover OAuth session from alternate cookies if needed
#     recover_oauth_session_from_cookies('microsoft', state_in_url)
    
#     current_app.logger.info(f"Final session state keys: {[k for k in session.keys() if k.startswith('_state_')]}")
    
#     # Get redirect URL from session
#     redirect_url = session.get('redirect_url', "https://mentormate-client.vercel.app/microsoft-callback")
    
#     try:
#         # Authlib automatically verifies state from session
#         current_app.logger.info("Calling authorize_access_token()...")
#         token = microsoft.authorize_access_token()
#         current_app.logger.info(f"Token received: {token is not None}")
#         if not token:
#             raise ValueError("Failed to get access token")

#         resp = microsoft.get('https://graph.microsoft.com/v1.0/me', token=token)
#         user_info = resp.json()
        
#         if not user_info or 'mail' not in user_info and 'userPrincipalName' not in user_info:
#             raise ValueError("Failed to get user info from Microsoft")

#         user_email = user_info.get('mail') or user_info.get('userPrincipalName')
        
#         if not user_email:
#             raise ValueError("No email found in user info")

#         # Check if user already has an active session - if so, remove it
#         active_session = AuthUtils.get_active_session_info(user_email)
#         if active_session:
#             AuthUtils.remove_user_session(user_email)
        
#         # Fetch profile picture using the helper function
#         profile_picture = get_microsoft_profile_picture(microsoft, token)

#         user_data = {
#             "name": user_info.get("displayName", "User"),
#             "email": user_email,
#             "picture": profile_picture,
#             "last_login": datetime.now(timezone.utc),
#             "auth_method": "microsoft"
#         }

#         result = users_collection.update_one(
#             {"email": user_data["email"]},
#             {"$set": user_data},
#             upsert=True
#         )

#         if result.upserted_id:
#             initialize_new_user_dashboard_stats(user_data["email"])

#         db_user = users_collection.find_one({"email": user_data["email"]})

#         # CRITICAL: Clear any old session data and regenerate session ID
#         # This prevents issues when browser sends multiple session cookies
#         session.clear()
        
#         session_id = AuthUtils.create_user_session(user_data["email"])

#         session.permanent = True
#         session['user'] = {
#             'email': db_user['email'],
#             'name': db_user['name'],
#             'picture': db_user['picture'],
#             'auth_method': db_user['auth_method'],
#             'premium': db_user.get('premium', False)
#         }
#         session['session_id'] = session_id
#         session.modified = True
        
#         # Log session creation for debugging
#         current_app.logger.info(f"Microsoft OAuth: Session created for {db_user['email']}")
#         current_app.logger.info(f"Session data: user={session.get('user')}, session_id={session.get('session_id')}")
#         current_app.logger.info(f"Session.permanent: {session.permanent}")
#         current_app.logger.info(f"Session.modified: {session.modified}")
        
#         params = {
#             "email": db_user["email"],
#             "name": db_user["name"],
#             "picture": db_user.get("picture", "/static/default-profile.png")
#         }
        
#         # Create session token for fallback (in case cookies are blocked)
#         session_token = session.sid if hasattr(session, 'sid') else str(uuid.uuid4())
#         params['session_token'] = session_token
        
#         final_redirect = f"{redirect_url}?{urlencode(params)}"
        
#         # CRITICAL FIX: Use server-side 302 redirect BEFORE creating response
#         # This preserves the Set-Cookie header in the HTTP response
#         # JavaScript redirects lose cookies because they're client-side navigation
#         current_app.logger.info(f"Microsoft OAuth: Using 302 redirect to preserve Set-Cookie")
#         response = redirect(final_redirect, code=302)
        
#         # CRITICAL: Mark session as modified and force save
#         session.modified = True
#         session.permanent = True
        
#         # Log what we're about to save (safe logging without slicing None values)
#         session_sid = getattr(session, 'sid', None)
#         session_sid_str = (str(session_sid)[:20] + '...' if session_sid else 'NO SID')
#         current_app.logger.info(f"🔍 DEBUG: Session data before save:")
#         current_app.logger.info(f"   - session.sid: {session_sid_str}")
        
#         user_email = session.get('user', {}).get('email', 'NO EMAIL')
#         # Only log email if it's not the default (safer than logging full user object)
#         current_app.logger.info(f"   - session.user.email: {user_email if user_email != 'NO EMAIL' else 'NONE'}")
#         current_app.logger.info(f"   - session.permanent: {session.permanent}")
#         current_app.logger.info(f"   - session.modified: {session.modified}")
        
#         # Force session to be saved to MongoDB with proper cookie attributes
#         current_app.session_interface.save_session(current_app, session, response)
        
#         # CRITICAL: Verify Set-Cookie was added to response, if not add it manually
#         # This ensures the cookie reaches the browser even if Flask-Session fails
#         if not response.headers.get('Set-Cookie'):
#             current_app.logger.warning("⚠ Set-Cookie not auto-generated by Flask-Session, adding manually")
#             # Generate proper cookie with all required attributes
#             cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
#             if hasattr(session, 'sid'):
#                 session_value = session.sid
#             else:
#                 session_value = str(uuid.uuid4())
            
#             response.set_cookie(
#                 cookie_name,
#                 value=session_value,
#                 max_age=3600,  # 1 hour
#                 secure=True,
#                 httponly=True,
#                 samesite='None',
#                 path='/'
#             )
#             current_app.logger.info(f"✓ Manually set cookie: {cookie_name}")
#         else:
#             set_cookie = response.headers.get('Set-Cookie')
#             current_app.logger.info(f"✓ Set-Cookie auto-generated: {set_cookie[:150]}")
#             # Verify SameSite and Secure flags are present
#             if 'SameSite=None' in set_cookie and 'Secure' in set_cookie:
#                 current_app.logger.info("✓✓ Set-Cookie has SameSite=None and Secure flags")
#             else:
#                 current_app.logger.warning(f"⚠ Set-Cookie missing required flags. Full: {set_cookie}")
        
#         # DIAGNOSTIC: Verify session was saved to MongoDB (safe implementation)
#         try:
#             # Get MongoDB client and verify session was saved
#             mongo_client = current_app.config.get('SESSION_MONGODB')
#             db_name = current_app.config.get('SESSION_MONGODB_DB', 'geotech_db')
#             collection_name = current_app.config.get('SESSION_MONGODB_COLLECT', 'flask_sessions')
            
#             if mongo_client:
#                 session_collection = mongo_client[db_name][collection_name]
                
#                 # Only check if session has a sid attribute
#                 if hasattr(session, 'sid') and session.sid:
#                     session_sid = str(session.sid)  # Ensure it's a string before slicing
#                     session_sid_short = session_sid[:20] + '...' if len(session_sid) > 20 else session_sid
                    
#                     saved_session = session_collection.find_one({'id': session.sid})
#                     if saved_session:
#                         current_app.logger.info(f"✓ Session VERIFIED in MongoDB: {session_sid_short}")
#                     else:
#                         current_app.logger.error(f"✗ Session NOT found in MongoDB after save! SID: {session_sid_short}")
#                 else:
#                     current_app.logger.warning("⚠ Session has no sid attribute, skipping MongoDB verification")
#             else:
#                 current_app.logger.warning("⚠ SESSION_MONGODB not configured, skipping verification")
#         except AttributeError as e:
#             current_app.logger.error(f"✗ Config access error during MongoDB verification: {e}")
#         except Exception as e:
#             current_app.logger.error(f"✗ Unexpected error during MongoDB verification: {type(e).__name__}: {e}")
        
#         # Log the response headers to verify Set-Cookie is present
#         all_set_cookie_headers = response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else []
#         current_app.logger.info(f"📤 Response Set-Cookie headers count: {len(all_set_cookie_headers)}")
#         for idx, cookie_header in enumerate(all_set_cookie_headers):
#             current_app.logger.info(f"   [{idx}] {cookie_header[:150]}")
        
#         current_app.logger.info(f"Microsoft OAuth: Redirecting to {final_redirect}")
#         return response

#     except Exception as e:
#         current_app.logger.error(f"Error in Microsoft callback: {str(e)}")
#         import traceback
#         current_app.logger.error(traceback.format_exc())
#         session.clear()

#         return redirect(f"{redirect_url}?error=auth_failed&message={str(e)}")
    
def get_microsoft_profile_picture(microsoft, token):
    """Fetch user's profile picture from Microsoft Graph"""
    try:
        # Try to get the photo
        photo_resp = microsoft.get(
            'https://graph.microsoft.com/v1.0/me/photo/$value',
            token=token
        )
        
        if photo_resp.status_code == 200:
            # Convert binary image data to base64
            import base64
            photo_data = base64.b64encode(photo_resp.content).decode('utf-8')
            return f"data:image/jpeg;base64,{photo_data}"
    except Exception as e:
        current_app.logger.warning(f"Could not fetch Microsoft profile picture: {str(e)}")
    
    return "/static/default-profile.png"



# def handle_google_callback(google, users_collection, initialize_new_user_dashboard_stats):
#     current_app.logger.info("=== GOOGLE CALLBACK START ===")
#     current_app.logger.info(f"Request cookies: {list(request.cookies.keys())}")
#     current_app.logger.info(f"Session contains user: {'user' in session}")
    
#     state_in_url = request.args.get('state')
#     current_app.logger.info(f"State in URL: {state_in_url}")
    
#     # Attempt to recover OAuth session from alternate cookies if needed
#     recover_oauth_session_from_cookies('google', state_in_url)
    
#     current_app.logger.info(f"Final session state keys: {[k for k in session.keys() if k.startswith('_state_')]}")
    
#     # Get redirect URL from session (set in main.py /login endpoint)
#     redirect_url = session.get('redirect_url', 'https://mentormate-client.vercel.app/google-callback')
    
#     try:
#         # Authlib automatically verifies state from session
#         current_app.logger.info("Calling authorize_access_token()...")
#         token = google.authorize_access_token()
#         current_app.logger.info(f"Token received: {token is not None}")
#         if not token:
#             raise ValueError("Failed to get access token")

#         # Get user info from Google
#         resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
#         user_info = resp.json()
        
#         if not user_info or 'email' not in user_info:
#             raise ValueError("Failed to get user info")

#         # Check if user already has an active session - if so, remove it
#         active_session = AuthUtils.get_active_session_info(user_info["email"])
#         if active_session:
#             AuthUtils.remove_user_session(user_info["email"])

#         # Store user data in MongoDB
#         user_data = {
#             "name": user_info.get("name", "User"),
#             "email": user_info["email"],
#             "picture": get_google_profile_picture(google, token) if not user_info.get("picture") else user_info.get("picture", "/static/default-profile.png"),
#             "last_login": datetime.now(timezone.utc),
#             "auth_method": "google"
#         }

#         # Update user or create if doesn't exist
#         result = users_collection.update_one(
#             {"email": user_data["email"]},
#             {"$set": user_data},
#             upsert=True
#         )

#         # Initialize dashboard stats for new users
#         if result.upserted_id:
#             initialize_new_user_dashboard_stats(user_data["email"])

#         # Fetch the full user record (including premium status)
#         db_user = users_collection.find_one({"email": user_data["email"]})

#         # CRITICAL: Clear any old session data and regenerate session ID
#         # This prevents issues when browser sends multiple session cookies
#         session.clear()
        
#         # Create new session
#         session_id = AuthUtils.create_user_session(user_data["email"]) 

#         # Set session, include premium status if present
#         session.permanent = True
#         session['user'] = {
#             'email': db_user['email'],
#             'name': db_user['name'],
#             'picture': db_user['picture'],
#             'auth_method': db_user['auth_method'],
#             'premium': db_user.get('premium', False)
#         }
#         session['session_id'] = session_id
#         session.modified = True
        
#         # Log session creation for debugging
#         current_app.logger.info(f"Google OAuth: Session created for {db_user['email']}")
#         current_app.logger.info(f"Session data: user={session.get('user')}, session_id={session.get('session_id')}")
#         current_app.logger.info(f"Session.permanent: {session.permanent}")
#         current_app.logger.info(f"Session.modified: {session.modified}")
        
#         # Create session token for fallback (in case cookies are blocked)
#         session_token = session.sid if hasattr(session, 'sid') else str(uuid.uuid4())
        
#         # Redirect to frontend with user info and session token
#         from urllib.parse import quote
#         redirect_params = f"email={quote(db_user['email'])}&name={quote(db_user['name'])}&picture={quote(db_user.get('picture', '/static/default-profile.png'))}&session_token={session_token}"
#         final_redirect = f"{redirect_url}?{redirect_params}"
        
#         # CRITICAL FIX: Use server-side 302 redirect BEFORE creating response
#         # This preserves the Set-Cookie header in the HTTP response
#         # JavaScript redirects lose cookies because they're client-side navigation
#         current_app.logger.info(f"Google OAuth: Using 302 redirect to preserve Set-Cookie")
#         response = redirect(final_redirect, code=302)
        
#         # CRITICAL: Mark session as modified and force save
#         session.modified = True
#         session.permanent = True
        
#         # Log what we're about to save (safe logging without slicing None values)
#         session_sid = getattr(session, 'sid', None)
#         session_sid_str = (str(session_sid)[:20] + '...' if session_sid else 'NO SID')
#         current_app.logger.info(f"🔍 DEBUG: Session data before save:")
#         current_app.logger.info(f"   - session.sid: {session_sid_str}")
        
#         user_email = session.get('user', {}).get('email', 'NO EMAIL')
#         # Only log email if it's not the default (safer than logging full user object)
#         current_app.logger.info(f"   - session.user.email: {user_email if user_email != 'NO EMAIL' else 'NONE'}")
#         current_app.logger.info(f"   - session.permanent: {session.permanent}")
#         current_app.logger.info(f"   - session.modified: {session.modified}")
        
#         # Force session to be saved to MongoDB with proper cookie attributes
#         current_app.session_interface.save_session(current_app, session, response)
        
#         # CRITICAL: Verify Set-Cookie was added to response, if not add it manually
#         # This ensures the cookie reaches the browser even if Flask-Session fails
#         if not response.headers.get('Set-Cookie'):
#             current_app.logger.warning("⚠ Set-Cookie not auto-generated by Flask-Session, adding manually")
#             # Generate proper cookie with all required attributes
#             cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
#             if hasattr(session, 'sid'):
#                 session_value = session.sid
#             else:
#                 session_value = str(uuid.uuid4())
            
#             response.set_cookie(
#                 cookie_name,
#                 value=session_value,
#                 max_age=3600,  # 1 hour
#                 secure=True,
#                 httponly=True,
#                 samesite='None',
#                 path='/'
#             )
#             current_app.logger.info(f"✓ Manually set cookie: {cookie_name} = {session_value[:20]}...")
#         else:
#             set_cookie = response.headers.get('Set-Cookie')
#             current_app.logger.info(f"✓ Set-Cookie auto-generated: {set_cookie[:200]}")
#             # Verify SameSite and Secure flags are present
#             if 'SameSite=None' in set_cookie and 'Secure' in set_cookie:
#                 current_app.logger.info("✓✓ Set-Cookie has SameSite=None and Secure flags")
#             else:
#                 current_app.logger.warning(f"⚠ Set-Cookie missing required flags. Full: {set_cookie}")
        
#         # DIAGNOSTIC: Verify session was saved to MongoDB (safe implementation)
#         try:
#             # Get MongoDB client and verify session was saved
#             mongo_client = current_app.config.get('SESSION_MONGODB')
#             db_name = current_app.config.get('SESSION_MONGODB_DB', 'geotech_db')
#             collection_name = current_app.config.get('SESSION_MONGODB_COLLECT', 'flask_sessions')
            
#             if mongo_client:
#                 session_collection = mongo_client[db_name][collection_name]
                
#                 # Only check if session has a sid attribute
#                 if hasattr(session, 'sid') and session.sid:
#                     session_sid = str(session.sid)  # Ensure it's a string before slicing
#                     session_sid_short = session_sid[:20] + '...' if len(session_sid) > 20 else session_sid
                    
#                     saved_session = session_collection.find_one({'id': session.sid})
#                     if saved_session:
#                         current_app.logger.info(f"✓ Session VERIFIED in MongoDB: {session_sid_short}")
#                     else:
#                         current_app.logger.error(f"✗ Session NOT found in MongoDB after save! SID: {session_sid_short}")
#                 else:
#                     current_app.logger.warning("⚠ Session has no sid attribute, skipping MongoDB verification")
#             else:
#                 current_app.logger.warning("⚠ SESSION_MONGODB not configured, skipping verification")
#         except AttributeError as e:
#             current_app.logger.error(f"✗ Config access error during MongoDB verification: {e}")
#         except Exception as e:
#             current_app.logger.error(f"✗ Unexpected error during MongoDB verification: {type(e).__name__}: {e}")
        
#         # Log the response headers to verify Set-Cookie is present
#         all_set_cookie_headers = response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else []
#         current_app.logger.info(f"📤 Response Set-Cookie headers count: {len(all_set_cookie_headers)}")
#         for idx, cookie_header in enumerate(all_set_cookie_headers):
#             current_app.logger.info(f"   [{idx}] {cookie_header[:150]}")
        
#         current_app.logger.info(f"Google OAuth: Redirecting to {final_redirect}")
#         return response

#     except Exception as e:
#         current_app.logger.error(f"Error in Google callback: {str(e)}")
#         import traceback
#         current_app.logger.error(traceback.format_exc())
#         session.clear()
        
#         # Use the redirect_url defined at the top
#         return redirect(f"{redirect_url}?error=auth_failed&message={str(e)}")

def handle_google_callback(google, users_collection, initialize_new_user_dashboard_stats):
    """
    UPDATED: Google OAuth callback with Partitioned cookie support
    """
    current_app.logger.info("=== GOOGLE CALLBACK START ===")
    current_app.logger.info(f"Request cookies: {list(request.cookies.keys())}")
    current_app.logger.info(f"Session contains user: {'user' in session}")
    
    state_in_url = request.args.get('state')
    current_app.logger.info(f"State in URL: {state_in_url}")
    
    # Attempt to recover OAuth session from alternate cookies if needed
    recover_oauth_session_from_cookies('google', state_in_url)
    
    current_app.logger.info(f"Final session state keys: {[k for k in session.keys() if k.startswith('_state_')]}")
    
    # Get redirect URL from session
    redirect_url = session.get('redirect_url', 'https://mentormate-client.vercel.app/google-callback')
    
    try:
        # Authlib automatically verifies state from session
        current_app.logger.info("Calling authorize_access_token()...")
        token = google.authorize_access_token()
        current_app.logger.info(f"Token received: {token is not None}")
        if not token:
            raise ValueError("Failed to get access token")

        # Get user info from Google
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
        user_info = resp.json()
        
        if not user_info or 'email' not in user_info:
            raise ValueError("Failed to get user info")

        # Check if user already has an active session - if so, remove it
        active_session = AuthUtils.get_active_session_info(user_info["email"])
        if active_session:
            AuthUtils.remove_user_session(user_info["email"])

        # Store user data in MongoDB
        user_data = {
            "name": user_info.get("name", "User"),
            "email": user_info["email"],
            "picture": user_info.get("picture", "/static/default-profile.png"),
            "last_login": datetime.now(timezone.utc),
            "auth_method": "google"
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

        # Fetch the full user record
        db_user = users_collection.find_one({"email": user_data["email"]})

        # CRITICAL: Clear any old session data
        session.clear()
        
        # Create new session
        session_id = AuthUtils.create_user_session(user_data["email"])

        # Set session data
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
        
        current_app.logger.info(f"Google OAuth: Session created for {db_user['email']}")
        
        # Create session token for fallback
        session_token = session.sid if hasattr(session, 'sid') else str(uuid.uuid4())
        
        # Build redirect URL
        from urllib.parse import quote
        redirect_params = f"email={quote(db_user['email'])}&name={quote(db_user['name'])}&picture={quote(db_user.get('picture', '/static/default-profile.png'))}&session_token={session_token}"
        final_redirect = f"{redirect_url}?{redirect_params}"
        
        # Create 302 redirect response
        current_app.logger.info(f"Google OAuth: Using 302 redirect")
        response = make_response(redirect(final_redirect, code=302))
        
        # CRITICAL: Force session save to MongoDB FIRST
        session.modified = True
        session.permanent = True
        current_app.session_interface.save_session(current_app, session, response)
        
        # NEW: Add Partitioned attribute for Safari/Brave
        response = add_partitioned_to_response(response)
        
        # Verify and log cookie headers
        set_cookie_headers = response.headers.getlist('Set-Cookie')
        current_app.logger.info(f"📤 Response Set-Cookie headers: {len(set_cookie_headers)}")
        
        for idx, cookie in enumerate(set_cookie_headers):
            current_app.logger.info(f"   [{idx}] {cookie[:200]}")
            
            # Check for required attributes
            if 'Partitioned' in cookie:
                current_app.logger.info("   ✓ Has Partitioned attribute")
            if 'SameSite=None' in cookie and 'Secure' in cookie:
                current_app.logger.info("   ✓ Has SameSite=None and Secure")
        
        # Verify MongoDB save
        try:
            mongo_client = current_app.config.get('SESSION_MONGODB')
            db_name = current_app.config.get('SESSION_MONGODB_DB', 'geotech_db')
            collection_name = current_app.config.get('SESSION_MONGODB_COLLECT', 'flask_sessions')
            
            if mongo_client and hasattr(session, 'sid'):
                session_collection = mongo_client[db_name][collection_name]
                saved_session = session_collection.find_one({'id': session.sid})
                
                if saved_session:
                    current_app.logger.info(f"✓ Session verified in MongoDB")
                else:
                    current_app.logger.error(f"✗ Session NOT in MongoDB!")
        except Exception as e:
            current_app.logger.error(f"MongoDB verification failed: {e}")
        
        current_app.logger.info(f"Redirecting to {final_redirect[:100]}...")
        return response

    except Exception as e:
        current_app.logger.error(f"Error in Google callback: {str(e)}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        session.clear()
        return redirect(f"{redirect_url}?error=auth_failed&message={str(e)}")
    
def get_google_profile_picture(google, token):

    try:
        # Get user info which includes the picture URL
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
        
        if resp.status_code == 200:
            user_info = resp.json()
            picture_url = user_info.get('picture')
            
            if picture_url:
                return picture_url
                
    except Exception as e:
        current_app.logger.warning(f"Could not fetch Google profile picture: {str(e)}")

    return "/static/default-profile.png"
    
def handle_user_profile(users_collection, db):
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


def handle_invalidate_session():
    try:
        user_email = session.get('user', {}).get('email')
        if user_email:
            # Remove the current session
            #remove_user_session(user_email)
            AuthUtils.remove_user_session(user_email)
        # Clear the session
        session.clear()
        return jsonify({'success': True, 'message': 'Session invalidated'})
        
    except Exception as e:
        current_app.logger.error(f"Error invalidating session: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to invalidate session'}), 500
    

def handle_unsubscription(users_collection, PAYFAST_SANDBOX):
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
    
