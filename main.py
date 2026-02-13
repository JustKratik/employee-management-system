import os
import json
import logging
from functools import lru_cache, wraps
from datetime import datetime

from flask import Flask, jsonify, request, send_file, send_from_directory, render_template, session, redirect, url_for
from flask_cors import CORS
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# =============================================================
# APP SETUP
# =============================================================
app = Flask(__name__, static_folder="static")
CORS(app)  # Allow cross-origin requests

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
SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
DEFAULT_SHEET_ID = os.environ.get(
    "GOOGLE_SHEET_ID", "1lemebG36uQ9MlbKZC_O2H_ltJZZI8aXFlnWlMbD4MXA"
)
RANGE_NAME = os.environ.get("SHEET_RANGE", "Admin_Sheet!A1:Z2000")

# --- Security Config (UPDATED) ---
# 1. Try to load from local secrets.py (Laptop Mode)
try:
    import secrets
    app.secret_key = secrets.SECRET_KEY
    ADMIN_PASSWORD = secrets.ADMIN_PASSWORD
    logger.info("✅ Loaded passwords from local secrets.py")

# 2. If secrets.py is missing (Render Mode), look in Environment Variables
except ImportError:
    app.secret_key = os.environ.get("SECRET_KEY")
    ADMIN_PASSWORD = os.environ.get("SITE_PASSWORD")
    logger.info("☁️  Loaded passwords from Environment Variables")

# Safety Check
if not ADMIN_PASSWORD:
    logger.warning("⚠️  WARNING: SITE_PASSWORD is not set! Login will be impossible.")


# =============================================================
# SECURITY DECORATOR
# =============================================================
def login_required(f):
    """
    A 'Decorator' that acts as a Security Guard.
    It checks if the user has a 'logged_in' ticket in their session.
    If not, it kicks them to the /login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# =============================================================
# GOOGLE CREDENTIALS
# =============================================================
_cached_creds = None

def get_google_creds():
    """
    Load Google OAuth2 credentials with caching and refresh logic.
    """
    global _cached_creds

    if _cached_creds and _cached_creds.valid:
        return _cached_creds

    creds = None

    # 1. Try environment variable
    token_json_str = os.environ.get("GOOGLE_TOKEN_JSON")
    if token_json_str:
        try:
            info = json.loads(token_json_str)
            creds = Credentials.from_authorized_user_info(info, SCOPES)
            logger.info("Loaded credentials from GOOGLE_TOKEN_JSON env var")
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to parse GOOGLE_TOKEN_JSON: %s", e)

    # 2. Fallback to token.json file
    if not creds and os.path.exists("token.json"):
        try:
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
            logger.info("Loaded credentials from token.json file")
        except Exception as e:
            logger.error("Failed to load token.json: %s", e)

    # 3. Refresh if expired
    if creds and not creds.valid:
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Refreshed expired credentials")
                # Update file if using file-based auth
                if not token_json_str and os.path.exists("token.json"):
                    with open("token.json", "w") as f:
                        f.write(creds.to_json())
            except Exception as e:
                logger.error("Failed to refresh credentials: %s", e)
                return None
        else:
            logger.warning("Credentials invalid and cannot be refreshed")
            return None

    _cached_creds = creds
    return creds


# =============================================================
# ROUTES
# =============================================================

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Serve the login page and handle password verification."""
    error = None
    if request.method == 'POST':
        # Check against the configured password
        if request.form.get('password') == ADMIN_PASSWORD:
            session['logged_in'] = True
            logger.info("User logged in successfully")
            return redirect(url_for('index'))
        else:
            logger.warning("Failed login attempt")
            error = 'Invalid Password'
    
    # Flask looks for this file in the 'templates' folder
    return render_template('login.html', error=error)


@app.route("/logout")
def logout():
    """Clear the session and send user back to login."""
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route("/")
@login_required  # <--- PROTECTED
def index():
    """Serve the main organization chart page."""
    return render_template("index.html")


@app.route("/api/employees")
@login_required  # <--- PROTECTED
def get_employees():
    """Fetch employee data from Google Sheets."""
    logger.info("--- /api/employees request ---")

    creds = get_google_creds()
    if not creds:
        logger.error("Authentication failed — no valid credentials")
        return jsonify({"error": "Authentication failed. Check server credentials."}), 500

    sheet_id = request.args.get("sheet", DEFAULT_SHEET_ID)
    range_name = request.args.get("range", RANGE_NAME)

    try:
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        result = (
            service.spreadsheets()
            .values()
            .get(spreadsheetId=sheet_id, range=range_name)
            .execute()
        )
    except HttpError as e:
        logger.error("Google Sheets API error: %s", e)
        return jsonify({"error": f"Google Sheets API error: {e.reason}"}), 502
    except Exception as e:
        logger.error("Unexpected error calling Google Sheets: %s", e)
        return jsonify({"error": "Failed to fetch data from Google Sheets"}), 500

    values = result.get("values", [])
    if not values:
        logger.warning("Sheet returned 0 rows")
        return jsonify([])

    headers = values[0]
    
    data = []
    for row in values[1:]:
        row += [""] * (len(headers) - len(row))
        data.append(dict(zip(headers, row)))

    return jsonify(data)


@app.route("/health")
def health():
    """Health check (Publicly accessible)."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
    })

# =============================================================
# ERROR HANDLERS
# =============================================================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error("Internal server error: %s", e)
    return jsonify({"error": "Internal server error"}), 500

# =============================================================
# ENTRY POINT
# =============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info("Starting server on 0.0.0.0:%d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)