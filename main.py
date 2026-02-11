import os
import json
import logging
from functools import lru_cache
from datetime import datetime

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# =============================================================
# APP SETUP
# =============================================================
app = Flask(__name__, static_folder="static")
CORS(app)  # Allow cross-origin requests (useful for API consumers)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# =============================================================
# CONFIGURATION  (env-var first, fallback to defaults)
# =============================================================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
DEFAULT_SHEET_ID = os.environ.get(
    "GOOGLE_SHEET_ID", "1lemebG36uQ9MlbKZC_O2H_ltJZZI8aXFlnWlMbD4MXA"
)
RANGE_NAME = os.environ.get("SHEET_RANGE", "Admin_Sheet!A1:Z2000")


# =============================================================
# GOOGLE CREDENTIALS  (env-var → file → fail gracefully)
# =============================================================
_cached_creds = None


def get_google_creds():
    """
    Load Google OAuth2 credentials.
    Priority:
      1. GOOGLE_TOKEN_JSON  env-var  (for Render / Docker / CI)
      2. token.json  file             (for local dev)
    Automatically refreshes expired tokens.
    """
    global _cached_creds

    # Return cached creds if still valid
    if _cached_creds and _cached_creds.valid:
        return _cached_creds

    creds = None

    # --- 1. Try environment variable ---
    token_json_str = os.environ.get("GOOGLE_TOKEN_JSON")
    if token_json_str:
        try:
            info = json.loads(token_json_str)
            creds = Credentials.from_authorized_user_info(info, SCOPES)
            logger.info("Loaded credentials from GOOGLE_TOKEN_JSON env var")
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to parse GOOGLE_TOKEN_JSON: %s", e)

    # --- 2. Fallback to token.json file ---
    if not creds and os.path.exists("token.json"):
        try:
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
            logger.info("Loaded credentials from token.json file")
        except Exception as e:
            logger.error("Failed to load token.json: %s", e)

    # --- 3. Refresh if expired ---
    if creds and not creds.valid:
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Refreshed expired credentials")

                # Persist refreshed token locally (only if using file-based auth)
                if not token_json_str and os.path.exists("token.json"):
                    with open("token.json", "w") as f:
                        f.write(creds.to_json())
                    logger.info("Saved refreshed token to token.json")
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
@app.route("/")
def index():
    """Serve the main organization chart page."""
    return send_file("index.html")


@app.route("/api/employees")
def get_employees():
    """
    Fetch employee data from Google Sheets.
    Optional query params:
      - sheet: Google Sheet ID (defaults to DEFAULT_SHEET_ID)
      - range: Sheet range   (defaults to RANGE_NAME)
    Returns JSON array of employee objects.
    """
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
    logger.info("✅ %d rows fetched  |  Headers: %s", len(values), headers)

    data = []
    for row in values[1:]:
        # Pad short rows so every row has the same number of columns
        row += [""] * (len(headers) - len(row))
        data.append(dict(zip(headers, row)))

    return jsonify(data)


@app.route("/health")
def health():
    """Health check for Render / load-balancers / uptime monitors."""
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
    logger.info("Starting server on 0.0.0.0:%d  (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
