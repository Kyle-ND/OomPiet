from functools import wraps
from flask import make_response, session, current_app, request
import re

def add_partitioned_attribute(response):
    """
    Add Partitioned attribute to session cookies for Safari compatibility.
    
    Safari 16.4+ requires the Partitioned attribute (CHIPS) for cross-site cookies.
    This function modifies Set-Cookie headers after Flask sets them.
    
    Args:
        response: Flask response object
        
    Returns:
        Modified response with Partitioned cookies
    """
    # Get all Set-Cookie headers
    cookies = response.headers.getlist('Set-Cookie')
    
    if not cookies:
        return response
    
    # Clear existing Set-Cookie headers
    response.headers.remove('Set-Cookie')
    
    # Get session cookie name from config
    session_cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
    
    # Process each cookie
    for cookie in cookies:
        # Only modify session cookies, not CSRF or other cookies
        if session_cookie_name in cookie:
            # Check if Partitioned is already present
            if 'Partitioned' not in cookie and 'partitioned' not in cookie.lower():
                # Add Partitioned attribute
                # Remove trailing semicolon if present, add Partitioned, then add semicolon back
                cookie = cookie.rstrip(';').rstrip() + '; Partitioned'
                
                current_app.logger.info(f"✓ Added Partitioned attribute to session cookie")
        
        # Add the (possibly modified) cookie back
        response.headers.add('Set-Cookie', cookie)
    
    return response


def with_partitioned_cookie(f):
    """
    Decorator to automatically add Partitioned attribute to session cookies.
    Use this on routes that create or modify sessions (login, OAuth callbacks).
    
    Usage:
        @app.route('/login')
        @with_partitioned_cookie
        def login():
            # Your login logic
            return response
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Call the original function
        result = f(*args, **kwargs)
        
        # Convert to response object if needed
        response = make_response(result)
        
        # Add Partitioned attribute
        response = add_partitioned_attribute(response)
        
        return response
    
    return decorated_function


def force_session_save(response):
    """
    Force immediate session save to MongoDB with write concern.
    Ensures session data is persisted before the response is sent.
    
    Args:
        response: Flask response object
        
    Returns:
        Response object (unmodified)
    """
    try:
        # Mark session as modified to force save
        session.modified = True
        
        # Get MongoDB configuration
        mongo_client = current_app.config.get('SESSION_MONGODB')
        db_name = current_app.config.get('SESSION_MONGODB_DB', 'geotech_db')
        collection_name = current_app.config.get('SESSION_MONGODB_COLLECT', 'flask_sessions')
        
        if not mongo_client:
            current_app.logger.warning("SESSION_MONGODB not configured, cannot force save")
            return response
        
        # Get session collection
        session_collection = mongo_client[db_name][collection_name]
        
        # Get session ID from cookie or session object
        session_id = None
        if hasattr(session, 'sid'):
            session_id = session.sid
        else:
            # Try to extract from Set-Cookie header
            set_cookie = response.headers.get('Set-Cookie', '')
            cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'google-login-session')
            match = re.search(rf'{cookie_name}=([^;]+)', set_cookie)
            if match:
                cookie_value = match.group(1)
                session_id = cookie_value.split('.')[0] if '.' in cookie_value else cookie_value
        
        if not session_id:
            current_app.logger.warning("Could not determine session ID for forced save")
            return response
        
        # Manually serialize and save session
        import pickle
        from datetime import datetime, timedelta
        
        session_doc = {
            'id': session_id,
            'val': pickle.dumps(dict(session)),
            'expiration': datetime.utcnow() + timedelta(hours=1)
        }
        
        # Use replace_one with upsert and write concern
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
    
    Usage:
        @app.route('/google/callback')
        @enhanced_oauth_callback_wrapper
        def google_callback():
            # Your callback logic
            return redirect(...)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_app.logger.info(f"=== ENHANCED OAUTH CALLBACK: {f.__name__} ===")
        
        # Call the original function
        result = f(*args, **kwargs)
        
        # Convert to response object
        response = make_response(result)
        
        # Step 1: Force session save to MongoDB
        response = force_session_save(response)
        
        # Step 2: Add Partitioned attribute for Safari
        response = add_partitioned_attribute(response)
        
        # Step 3: Verify cookie headers are present
        set_cookie_headers = response.headers.getlist('Set-Cookie')
        current_app.logger.info(f"📤 Final Set-Cookie headers: {len(set_cookie_headers)}")
        
        for idx, cookie in enumerate(set_cookie_headers):
            current_app.logger.info(f"   [{idx}] {cookie[:150]}...")
            
            # Verify required attributes
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
    
    Args:
        app: Flask application instance
    """
    # Ensure all required settings are configured
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'None')
    app.config.setdefault('SESSION_COOKIE_SECURE', True)
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_PERMANENT', True)
    app.config.setdefault('SESSION_COOKIE_DOMAIN', None)  # Let browser handle domain
    
    # Add after_request handler to add Partitioned to all session cookies
    @app.after_request
    def auto_add_partitioned(response):
        # Only add Partitioned to session cookies, not all responses
        if 'Set-Cookie' in response.headers:
            response = add_partitioned_attribute(response)
        return response
    
    app.logger.info("✓ Cross-site session configuration applied")
    app.logger.info(f"  - SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE')}")
    app.logger.info(f"  - SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE')}")
    app.logger.info(f"  - Partitioned attribute: AUTO-APPLIED")