import os
import json
import logging
import time
from functools import wraps
from datetime import datetime

from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# =============================================================
# APP SETUP
# =============================================================
app = Flask(__name__, static_folder="static")
CORS(app)  # Allow cross-origin requests

# --- CRITICAL FIX FOR LOCALHOST LOGIN ---
# This allows OAuth to work over HTTP (localhost) instead of requiring HTTPS.
# Without this, you get the "mismatching_state" / CSRF error.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# =============================================================
# CONFIGURATION
# =============================================================
# 1. Sheets Config
SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
DEFAULT_SHEET_ID = os.environ.get(
    "GOOGLE_SHEET_ID", "1lemebG36uQ9MlbKZC_O2H_ltJZZI8aXFlnWlMbD4MXA"
)
RANGE_NAME = os.environ.get("SHEET_RANGE", "Admin_Sheet")

# Look for emails in Column B of the 'Access' tab
ACCESS_SHEET_RANGE = "Access!B:B"

# 2. Security Keys (Load from secrets.py or Environment)
try:
    import secrets
    app.secret_key = secrets.SECRET_KEY
    logger.info("✅ Loaded SECRET_KEY from local secrets.py")
except (ImportError, AttributeError):
    app.secret_key = os.environ.get("SECRET_KEY", "default-dev-key")
    logger.info("☁️  Loaded SECRET_KEY from Environment")

# =============================================================
# OAUTH SETUP
# =============================================================
oauth = OAuth(app)

def load_google_config():
    """
    Robustly load Google Config from File (Local) or Env Var (Render).
    Handles both 'web' and 'installed' JSON formats automatically.
    """
    config_data = None

    # 1. Try Local File
    if os.path.exists("google_client_secret.json"):
        logger.info("🔐 Loading auth config from local file")
        try:
            with open("google_client_secret.json", "r") as f:
                config_data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read local JSON file: {e}")

    # 2. Try Environment Variable (Render)
    elif os.environ.get("GOOGLE_CLIENT_SECRET_JSON"):
        logger.info("☁️  Loading auth config from Environment")
        try:
            config_data = json.loads(os.environ.get("GOOGLE_CLIENT_SECRET_JSON"))
        except Exception as e:
            logger.error(f"Failed to parse GOOGLE_CLIENT_SECRET_JSON: {e}")

    if not config_data:
        return None

    # 3. Smart Extraction (Find the credentials wherever they are hiding)
    if 'web' in config_data:
        return config_data['web']
    elif 'installed' in config_data:
        return config_data['installed']
    else:
        # Fallback: The JSON might be the credentials themselves
        return config_data

# Register Google OAuth
google_creds = load_google_config()
if google_creds:
    oauth.register(
        name='google',
        client_id=google_creds['client_id'],
        client_secret=google_creds['client_secret'],
        # IMPORTANT: This URL tells Authlib where to find authorize_url and token_url
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
else:
    logger.warning("⚠️  NO GOOGLE LOGIN CONFIG FOUND! Login will fail.")


# =============================================================
# HELPER: GOOGLE SHEETS & ACCESS CONTROL (WITH CACHE)
# =============================================================
# --- Global Cache Variables ---
CACHED_ALLOWED_EMAILS = set()  # Store valid emails here
LAST_CACHE_UPDATE = 0          # Time of last update
CACHE_DURATION = 60            # Keep cache valid for 60 seconds

def get_google_creds():
    """Load Service Account Credentials for reading the Sheets."""
    creds = None
    
    # 1. Try Environment Variable (Render)
    token_json_str = os.environ.get("GOOGLE_TOKEN_JSON")
    if token_json_str:
        try:
            info = json.loads(token_json_str)
            creds = Credentials.from_authorized_user_info(info, SCOPES)
        except Exception:
            pass

    # 2. Try Local File (Laptop)
    if not creds and os.path.exists("token.json"):
        try:
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        except Exception:
            pass

    # 3. Refresh if needed
    if creds and not creds.valid:
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                logger.error(f"Failed to refresh creds: {e}")
                return None
    return creds

def check_user_access(email):
    """
    Check if email is authorized. Uses a cache to avoid hitting Google API too often.
    """
    global CACHED_ALLOWED_EMAILS, LAST_CACHE_UPDATE
    
    current_time = time.time()
    
    # --- 1. Check Cache Validity (Is cache expired or empty?) ---
    if not CACHED_ALLOWED_EMAILS or (current_time - LAST_CACHE_UPDATE > CACHE_DURATION):
        logger.info("🔄 Refreshing Allowed Emails Cache from Google Sheet...")
        
        creds = get_google_creds()
        if not creds:
            logger.error("Cannot check access: Server credentials missing")
            # If API fails, maybe keep old cache as fallback? Let's play it safe and return False.
            return False

        try:
            service = build("sheets", "v4", credentials=creds)
            # Fetch Column B from 'Access' tab
            result = service.spreadsheets().values().get(
                spreadsheetId=DEFAULT_SHEET_ID, range=ACCESS_SHEET_RANGE
            ).execute()
            
            rows = result.get("values", [])
            
            # --- UPDATE CACHE ---
            # Create a set for fast lookup (O(1))
            new_allowed_emails = {str(r[0]).strip().lower() for r in rows if r}
            CACHED_ALLOWED_EMAILS = new_allowed_emails
            LAST_CACHE_UPDATE = current_time
            logger.info(f"✅ Cache Updated. Total Authorized Users: {len(CACHED_ALLOWED_EMAILS)}")
            
        except Exception as e:
            logger.error(f"Error reading Access sheet: {e}")
            # If Google fails, return False unless we have a stale cache?
            # For security, failing is safer than allowing unintended access.
            return False

    # --- 2. Check the (Cached) List ---
    user_email = str(email).strip().lower()
    
    if user_email in CACHED_ALLOWED_EMAILS:
        return True
    else:
        logger.warning(f"⛔ Access denied for: {user_email}")
        return False

# =============================================================
# SECURITY DECORATOR (UPDATED TO RE-CHECK ACCESS)
# =============================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = session.get('user')
        if not user:
            return redirect(url_for('login'))
        
        # --- NEW: CONTINUOUS AUTHORIZATION CHECK ---
        # Even if logged in, we check the sheet (via cache) on EVERY request.
        # This allows us to revoke access instantly by removing email from sheet.
        email = user.get('email')
        if not check_user_access(email):
            # User was logged in, but is no longer on the list!
            logger.warning(f"🚫 Session Revoked: {email} removed from Access Sheet")
            session.clear() # Destroy the session cookie immediately
            return get_access_denied_html(email)

        return f(*args, **kwargs)
    return decorated_function

def get_access_denied_html(email):
    """Returns the standard Access Denied HTML page."""
    return f"""
    <div style="text-align:center; padding-top:50px; font-family:sans-serif;">
        <h1 style="color:red;">Access Denied</h1>
        <p>The email <b>{email}</b> is not on the authorized list.</p>
        <p>Please contact the administrator to request access.</p>
        <br>
        <a href="/login?prompt=select_account" 
           style="background-color:#4285F4; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;">
           Try a different account
        </a>
    </div>
    """

# =============================================================
# ROUTES
# =============================================================

@app.route("/")
@login_required
def index():
    """Serve the main page."""
    # Pass user info to template so we can say "Hello, Name"
    return render_template("index.html", user=session.get('user'))

@app.route("/login")
def login():
    """Start the Google Login process with Debugging."""
    try:
        # 1. Print to logs so we know we got here
        logger.info("🚀 STARTING LOGIN PROCESS...")

        # 2. Check if the keys loaded correctly
        if not oauth.google:
            raise ValueError("OAuth client not registered! Check GOOGLE_CLIENT_SECRET_JSON.")

        # 3. Build the redirect
        redirect_uri = url_for('auth_callback', _external=True)

        # 4. Handle the 'Try different account' logic
        if request.args.get('prompt') == 'select_account':
            return oauth.google.authorize_redirect(redirect_uri, prompt='select_account')
        
        return oauth.google.authorize_redirect(redirect_uri)

    except Exception as e:
        # --- THE TRAP: Print the real error to the logs AND the browser ---
        logger.error(f"🔥 CRITICAL LOGIN ERROR: {str(e)}")
        import traceback
        traceback.print_exc()  # This forces the Python error into the Render logs
        return f"<h1>DEBUG ERROR:</h1><p>{str(e)}</p>", 500

@app.route("/callback")
def auth_callback():
    """Google redirects back here after user approves."""
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        
        # Fallback for some library versions
        if not user_info:
            user_info = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()

        email = user_info['email']
        logger.info(f"👤 Login attempt: {email}")
        
        # --- THE GATEKEEPER CHECK ---
        if check_user_access(email):
            session['user'] = user_info
            logger.info(f"✅ Access granted: {email}")
            return redirect(url_for('index'))
        else:
            return get_access_denied_html(email)
            
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return f"Login failed: {str(e)}"

@app.route("/logout")
def logout():
    """Clear session."""
    session.pop('user', None)
    return redirect(url_for('index'))  # Will redirect back to login

@app.route("/api/employees")
@login_required
def get_employees():
    """Fetch employee data (Protected)."""
    creds = get_google_creds()
    if not creds:
        return jsonify({"error": "Server configuration error"}), 500

    sheet_id = request.args.get("sheet", DEFAULT_SHEET_ID)
    range_name = request.args.get("range", RANGE_NAME)

    try:
        service = build("sheets", "v4", credentials=creds)
        result = service.spreadsheets().values().get(
            spreadsheetId=sheet_id, range=range_name
        ).execute()
        
        values = result.get("values", [])
        if not values: return jsonify([])
        
        headers = values[0]
        data = [dict(zip(headers, row + [""] * (len(headers) - len(row)))) for row in values[1:]]
        return jsonify(data)
        
    except Exception as e:
        logger.error(f"API Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "2.1.0"})

# =============================================================
# ERROR HANDLERS & ENTRY
# =============================================================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)