#!/usr/bin/env python3
"""
app.py - Flask backend for Gamified Disaster Preparedness & Response Education System

Features:
- JWT authentication
- Register / Login (email + password)
- Google Sign-In (ID token verification) or demo mode via ALLOW_INSECURE_GOOGLE
- Profile, module progress and image uploads (stored as base64)
- Serves frontend static files when available
- CORS configured to allow provided FRONTEND origin(s)
"""

import os
import base64
import binascii
import logging
from datetime import timedelta
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING
from passlib.hash import bcrypt
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.utils import secure_filename

# Optional Google verification
try:
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
    _HAS_GOOGLE_LIBS = True
except Exception:
    _HAS_GOOGLE_LIBS = False

# load environment file in dev
load_dotenv()

# -----------------------
# Configuration / env
# -----------------------
MONGO_URI = os.environ.get("MONGO_URI")
MONGO_DBNAME = os.environ.get("MONGO_DBNAME")  # optional
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
FRONTEND_DIR = os.environ.get("FRONTEND_DIR", "frontend")  # relative to this file
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "")   # optional origin to allow in CORS
ALLOW_INSECURE_GOOGLE = os.environ.get("ALLOW_INSECURE_GOOGLE", "0") == "1"
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "5"))

# Basic checks (clear messages)
missing = []
if not MONGO_URI:
    missing.append("MONGO_URI")
if not JWT_SECRET_KEY:
    missing.append("JWT_SECRET_KEY")
if not ADMIN_SECRET:
    missing.append("ADMIN_SECRET")
if not GOOGLE_CLIENT_ID and not ALLOW_INSECURE_GOOGLE:
    # allow ALLOW_INSECURE_GOOGLE for dev/demo only
    missing.append("GOOGLE_CLIENT_ID (or set ALLOW_INSECURE_GOOGLE=1 for dev)")

if missing:
    raise RuntimeError("Missing required env vars: " + ", ".join(missing))

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("lifesafe-backend")

# -----------------------
# Flask app
# -----------------------
BASE_DIR = Path(__file__).parent.resolve()
STATIC_DIR = (BASE_DIR / FRONTEND_DIR).resolve()

app = Flask(
    __name__,
    static_folder=str(STATIC_DIR) if STATIC_DIR.exists() else None,
    static_url_path=""
)
# configure CORS
cors_origins = []
if FRONTEND_ORIGIN:
    cors_origins.append(FRONTEND_ORIGIN)
else:
    # allow common local dev origins by default; on Render set FRONTEND_ORIGIN explicitly
    cors_origins += ["http://localhost:3000", "http://127.0.0.1:3000"]

CORS(app, origins=cors_origins)

# JWT
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=6)
jwt = JWTManager(app)

# Upload size cap
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# -----------------------
# MongoDB connection
# -----------------------
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # attempt server selection early to fail fast
    client.server_info()
    if MONGO_DBNAME:
        db = client.get_database(MONGO_DBNAME)
    else:
        # get_default_database works only if DB specified in URI
        try:
            db = client.get_default_database()
        except Exception:
            # fallback
            db = client.get_database("lifesafe")
    logger.info("Connected to MongoDB database: %s", db.name)
except Exception as e:
    logger.exception("Failed to connect to MongoDB: %s", e)
    raise

# Collections
users_col = db["users"]
profiles_col = db["profiles"]
progress_col = db["module_progress"]
images_col = db["uploads"]

# Ensure indexes (don't crash on index errors)
try:
    users_col.create_index([("email", ASCENDING)], unique=True)
    profiles_col.create_index([("idNo", ASCENDING)], unique=True, sparse=True)
    progress_col.create_index([("user_email", ASCENDING), ("module_id", ASCENDING)], unique=True, sparse=True)
except Exception as e:
    logger.warning("Index creation issue: %s", e)

# -----------------------
# Helpers
# -----------------------
def hash_password(raw: str) -> str:
    return bcrypt.hash(raw)

def verify_password(hash_, raw: str) -> bool:
    try:
        return bcrypt.verify(raw, hash_)
    except Exception:
        return False

def user_public(user_doc, profile_doc=None):
    p = profile_doc or profiles_col.find_one({"user_email": user_doc["email"]}) or {}
    return {
        "email": user_doc.get("email"),
        "studentName": p.get("studentName", ""),
        "dob": p.get("dob"),
        "idNo": p.get("idNo"),
        "school": p.get("school", ""),
        "father": p.get("father", ""),
        "contact": p.get("contact", ""),
        "emergency": p.get("emergency", ""),
    }

def decode_base64_image(b64str):
    if "," in b64str:
        b64str = b64str.split(",", 1)[1]
    try:
        binary = base64.b64decode(b64str, validate=True)
        return binary, None
    except (binascii.Error, ValueError) as e:
        return None, "Invalid base64 data"

def create_user_if_missing(email):
    if not users_col.find_one({"email": email}):
        users_col.insert_one({"email": email, "password_hash": None})
        profiles_col.insert_one({"user_email": email, "studentName": email.split("@")[0], "xp": 0})

# -----------------------
@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return app.send_static_file(path)

# -----------------------
# Auth routes
# -----------------------
@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"ok": False, "message": "Invalid JSON body"}), 400

    required = ["studentName", "idNo", "email", "password"]
    for r in required:
        if not data.get(r):
            return jsonify({"ok": False, "message": f"{r} is required"}), 400

    email = data["email"].strip().lower()
    # simple uniqueness checks
    if users_col.find_one({"email": email}):
        return jsonify({"ok": False, "message": "Email already registered"}), 400
    if data.get("idNo") and profiles_col.find_one({"idNo": data["idNo"]}):
        return jsonify({"ok": False, "message": "ID/Aadhar already registered"}), 400

    pw_hash = hash_password(data["password"])
    users_col.insert_one({"email": email, "password_hash": pw_hash})
    profiles_col.insert_one({
        "user_email": email,
        "studentName": data.get("studentName"),
        "dob": data.get("dob"),
        "idNo": data.get("idNo"),
        "school": data.get("school"),
        "father": data.get("father"),
        "contact": data.get("contact"),
        "emergency": data.get("emergency"),
        "xp": 0
    })

    token = create_access_token(identity=email)
    return jsonify({"ok": True, "message": "Registered", "access": token}), 201

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"ok": False, "message": "Invalid JSON body"}), 400

    email = (data.get("email") or "").strip().lower()
    pwd = data.get("password") or ""
    user = users_col.find_one({"email": email})
    if not user or not verify_password(user.get("password_hash"), pwd):
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401
    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

@app.route("/api/google-signin", methods=["POST"])
def google_signin():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"ok": False, "message": "Invalid JSON body"}), 400

    id_token_str = data.get("id_token")
    email = None

    if id_token_str:
        if not _HAS_GOOGLE_LIBS:
            return jsonify({"ok": False, "message": "Google libraries not installed on server"}), 500
        try:
            idinfo = google_id_token.verify_oauth2_token(id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID)
            email = idinfo.get("email")
        except Exception as e:
            logger.exception("Google token verify failed: %s", e)
            return jsonify({"ok": False, "message": "Invalid Google token", "detail": str(e)}), 401
    elif ALLOW_INSECURE_GOOGLE:
        # demo mode: accept email in request (insecure)
        email = (data.get("email") or "").strip().lower()
    else:
        return jsonify({"ok": False, "message": "id_token required"}), 400

    if not email:
        return jsonify({"ok": False, "message": "No email found"}), 400
    create_user_if_missing(email)
    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

# -----------------------
# Profile & Progress
# -----------------------
@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    email = get_jwt_identity()
    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"ok": False, "message": "User not found"}), 404
    profile_doc = profiles_col.find_one({"user_email": email}) or {}
    return jsonify({"ok": True, "profile": user_public(user, profile_doc)})

@app.route("/api/module/<int:module_id>/progress", methods=["GET"])
@jwt_required()
def get_module_progress(module_id):
    email = get_jwt_identity()
    doc = progress_col.find_one({"user_email": email, "module_id": module_id})
    if not doc:
        return jsonify({"ok": True, "completed": [], "scores": {}, "uploads": []})
    return jsonify({
        "ok": True,
        "completed": doc.get("completed", []),
        "scores": doc.get("scores", {}),
        "uploads": doc.get("uploads", []),
    })

@app.route("/api/module/<int:module_id>/progress", methods=["POST"])
@jwt_required()
def save_module_progress(module_id):
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"ok": False, "message": "Invalid JSON body"}), 400
    email = get_jwt_identity()
    progress_col.update_one(
        {"user_email": email, "module_id": module_id},
        {"$set": {"completed": data.get("completed", []), "scores": data.get("scores", {})}},
        upsert=True
    )
    return jsonify({"ok": True, "message": "Progress saved"})

@app.route("/api/module/<int:module_id>/upload", methods=["POST"])
@jwt_required()
def upload_image(module_id):
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"ok": False, "message": "Invalid JSON body"}), 400

    email = get_jwt_identity()
    try:
        assignment = int(data.get("assignment", 0))
    except Exception:
        assignment = 0
    filename = secure_filename(data.get("filename", "upload.jpg") or "upload.jpg")
    b64 = data.get("b64")
    if not b64:
        return jsonify({"ok": False, "message": "No image data provided"}), 400

    binary, err = decode_base64_image(b64)
    if not binary:
        return jsonify({"ok": False, "message": err}), 400

    upload_doc = {"user_email": email, "module_id": module_id, "assignment": assignment,
                  "filename": filename, "b64": b64, "size": len(binary)}
    res = images_col.insert_one(upload_doc)
    upload_id = str(res.inserted_id)

    progress_col.update_one(
        {"user_email": email, "module_id": module_id},
        {"$push": {"uploads": {"upload_id": upload_id, "assignment": assignment, "filename": filename}}},
        upsert=True
    )
    return jsonify({"ok": True, "upload_id": upload_id})

# -----------------------
# Admin & Health
# -----------------------
@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    secret = request.headers.get("X-Admin-Secret")
    if secret != ADMIN_SECRET:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    users = []
    for u in users_col.find({}, {"password_hash": 0}):
        profile = profiles_col.find_one({"user_email": u["email"]}, {"_id": 0})
        progress = list(progress_col.find({"user_email": u["email"]}, {"_id": 0}))
        users.append({"email": u["email"], "profile": profile, "progress": progress})
    return jsonify({"ok": True, "users": users})

@app.route("/api/health", methods=["GET"])
def health():
    # quick DB ping
    try:
        client.admin.command("ping")
        db_name = db.name
    except Exception as e:
        logger.exception("DB ping failed: %s", e)
        return jsonify({"ok": False, "message": "DB connection error", "detail": str(e)}), 500
    return jsonify({"ok": True, "db": db_name})

# -----------------------
# Error handlers
# -----------------------
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"ok": False, "message": "Uploaded file too large"}), 413

@app.errorhandler(404)
def not_found(e):
    # Let static route decide if frontend fallback exists; otherwise return JSON for API paths
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "message": "Not found"}), 404
    return jsonify({"ok": False, "message": "Frontend not found on server."}), 404

@app.errorhandler(Exception)
def catch_all(e):
    logger.exception("Unhandled exception: %s", e)
    # For API paths return JSON; otherwise show minimal message
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "message": "Internal server error", "detail": str(e)}), 500
    return jsonify({"ok": False, "message": "Internal server error"}), 500

# -----------------------
# Run (development)
# -----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    logger.info("Starting app on port %d (debug=%s)", port, debug_mode)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
