"""
Cross-Site Session Cookie Fix for Flask
Adds Partitioned attribute and improved cookie handling for Safari/Brave compatibility
"""

from functools import wraps
from flask import make_response, session, current_app, request
import re


def add_partitioned_attribute(response):
    """
    Add Partitioned attribute to session cookies for Safari compatibility.
    Safari 16.4+ requires the Partitioned attribute (CHIPS) for cross-site cookies.
    This function modifies Set-Cookie headers after Flask sets them.
    """
    cookies = response.headers.getlist('Set-Cookie')
    if not cookies:
        return response
    response.headers.remove('Set-Cookie')
    session_cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
    for cookie in cookies:
        if session_cookie_name in cookie:
            if 'Partitioned' not in cookie and 'partitioned' not in cookie.lower():
                cookie = cookie.rstrip(';').rstrip() + '; Partitioned'
                current_app.logger.info(f"✓ Added Partitioned attribute to session cookie")
        response.headers.add('Set-Cookie', cookie)
    return response


def with_partitioned_cookie(f):
    """
    Decorator to automatically add Partitioned attribute to session cookies.
    Use this on routes that create or modify sessions (login, OAuth callbacks).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        result = f(*args, **kwargs)
        response = make_response(result)
        response = add_partitioned_attribute(response)
        return response
    return decorated_function


def force_session_save(response):
    """
    Force immediate session save to MongoDB with write concern.
    Ensures session data is persisted before the response is sent.
    """
    try:
        session.modified = True
        mongo_client = current_app.config.get('SESSION_MONGODB')
        db_name = current_app.config.get('SESSION_MONGODB_DB', 'geotech_db')
        collection_name = current_app.config.get('SESSION_MONGODB_COLLECT', 'flask_sessions')
        if not mongo_client:
            current_app.logger.warning("SESSION_MONGODB not configured, cannot force save")
            return response
        session_collection = mongo_client[db_name][collection_name]
        session_id = None
        if hasattr(session, 'sid'):
            session_id = session.sid
        else:
            set_cookie = response.headers.get('Set-Cookie', '')
            cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
            match = re.search(rf'{cookie_name}=([^;]+)', set_cookie)
            if match:
                cookie_value = match.group(1)
                session_id = cookie_value.split('.')[0] if '.' in cookie_value else cookie_value
        if not session_id:
            current_app.logger.warning("Could not determine session ID for forced save")
            return response
        import pickle
        from datetime import datetime, timedelta
        session_doc = {
            'id': session_id,
            'val': pickle.dumps(dict(session)),
            'expiration': datetime.utcnow() + timedelta(hours=1)
        }
        result = session_collection.replace_one(
            {'id': session_id},
            session_doc,
            upsert=True
        )
        if result.acknowledged:
            current_app.logger.info(f"✓ Session {session_id[:20]}... saved to MongoDB with acknowledgment")
        else:
            current_app.logger.error(f"✗ MongoDB write NOT acknowledged for session {session_id[:20]}...")
    except Exception as e:
        current_app.logger.error(f"Error in force_session_save: {type(e).__name__}: {e}")
    return response


def enhanced_oauth_callback_wrapper(f):
    """
    Enhanced decorator for OAuth callback routes.
    Combines partitioned cookies, forced session save, and verification.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_app.logger.info(f"=== ENHANCED OAUTH CALLBACK: {f.__name__} ===")
        result = f(*args, **kwargs)
        response = make_response(result)
        response = force_session_save(response)
        response = add_partitioned_attribute(response)
        set_cookie_headers = response.headers.getlist('Set-Cookie')
        current_app.logger.info(f"📤 Final Set-Cookie headers: {len(set_cookie_headers)}")
        for idx, cookie in enumerate(set_cookie_headers):
            current_app.logger.info(f"   [{idx}] {cookie[:150]}...")
            required_attrs = ['Secure', 'HttpOnly', 'SameSite=None', 'Partitioned']
            missing_attrs = [attr for attr in required_attrs if attr not in cookie]
            if missing_attrs:
                current_app.logger.warning(f"   ⚠ Missing attributes: {', '.join(missing_attrs)}")
        return response
    return decorated_function


def setup_cross_site_session_config(app):
    """
    Configure Flask app for optimal cross-site session handling.
    Call this once during app initialization.
    """
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'None')
    app.config.setdefault('SESSION_COOKIE_SECURE', True)
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_PERMANENT', True)
    app.config.setdefault('SESSION_COOKIE_DOMAIN', None)
    @app.after_request
    def auto_add_partitioned(response):
        if 'Set-Cookie' in response.headers:
            response = add_partitioned_attribute(response)
        return response
    app.logger.info("✓ Cross-site session configuration applied")
    app.logger.info(f"  - SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE')}")
    app.logger.info(f"  - SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE')}")
    app.logger.info(f"  - Partitioned attribute: AUTO-APPLIED")
