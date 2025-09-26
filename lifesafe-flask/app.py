"""
Gamified Disaster Preparedness & Response Education System Backend
Flask + MongoDB backend with JWT authentication and Google Sign-In.
"""

import os
import base64
import binascii
import logging
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING
from passlib.hash import bcrypt
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.utils import secure_filename

# Google token verification (optional)
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

load_dotenv()
logging.basicConfig(level=logging.INFO)

# ---------- ENV ----------
MONGO_URI = os.environ.get("MONGO_URI")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "")  # set to your frontend origin on Render
ALLOW_INSECURE_GOOGLE = os.environ.get("ALLOW_INSECURE_GOOGLE", "0") == "1"

# Basic validations (allowing insecure google for dev)
if not MONGO_URI:
    raise RuntimeError("MONGO_URI is required (set in environment).")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is required (set in environment).")
if not ADMIN_SECRET:
    raise RuntimeError("ADMIN_SECRET is required (set in environment).")
if not GOOGLE_CLIENT_ID and not ALLOW_INSECURE_GOOGLE:
    logging.warning("GOOGLE_CLIENT_ID not set and ALLOW_INSECURE_GOOGLE != 1; google sign-in will fail.")

# ---------- Flask app ----------
# adjust static_folder/static_url_path to match your repo if needed
app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), "frontend"),  # or ../frontend if layout differs
    static_url_path=""
)

# CORS: allow your frontend origin and localhost dev
allowed_origins = []
if FRONTEND_ORIGIN:
    allowed_origins.append(FRONTEND_ORIGIN)
allowed_origins += ["http://localhost:3000", "http://127.0.0.1:3000"]

# In production lock this to specific origins; for debug you can set origins="*"
CORS(app, origins=allowed_origins or "*", supports_credentials=True)

# JWT
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=6)
jwt = JWTManager(app)

# file upload limit
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", 5)) * 1024 * 1024

# ---------- MongoDB connection ----------
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    # trigger a server selection to get early error if credentials/whitelist wrong
    client.server_info()
    db = client.get_default_database()
    users_col = db["users"]
    profiles_col = db["profiles"]
    progress_col = db["module_progress"]
    images_col = db["uploads"]

    # indexes
    users_col.create_index([("email", ASCENDING)], unique=True)
    profiles_col.create_index([("idNo", ASCENDING)], unique=True, sparse=True)
    progress_col.create_index([("user_email", ASCENDING), ("module_id", ASCENDING)], unique=True, sparse=True)
    logging.info("Connected to MongoDB and ensured indexes.")
except Exception as e:
    logging.exception("Failed to connect to MongoDB. Check MONGO_URI and network/atlas whitelist.")
    raise

# ---------- helpers ----------
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
        "email": user_doc["email"],
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

# ---------- static frontend ----------
@app.route("/")
def index():
    try:
        return app.send_static_file("index.html")
    except Exception:
        return jsonify({"ok": False, "message": "Frontend not found on server."}), 404

@app.route("/<path:path>")
def static_proxy(path):
    try:
        return app.send_static_file(path)
    except Exception:
        return jsonify({"ok": False, "message": "Frontend asset not found."}), 404

# ---------- API routes (add robust JSON error handling) ----------
def safe_get_json():
    try:
        return request.get_json(force=True)
    except Exception as e:
        logging.exception("Invalid JSON on request")
        return None

@app.route("/api/register", methods=["POST"])
def register():
    data = safe_get_json()
    if not data:
        return jsonify({"ok": False, "message": "Invalid JSON in request"}), 400

    required = ["studentName", "idNo", "email", "password"]
    for r in required:
        if not data.get(r):
            return jsonify({"ok": False, "message": f"{r} is required"}), 400

    email = data["email"].strip().lower()
    if users_col.find_one({"email": email}):
        return jsonify({"ok": False, "message": "Email already registered"}), 400
    if data.get("idNo") and profiles_col.find_one({"idNo": data["idNo"]}):
        return jsonify({"ok": False, "message": "ID/Aadhar already registered"}), 400

    try:
        users_col.insert_one({"email": email, "password_hash": hash_password(data["password"])})
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
    except Exception as e:
        logging.exception("Error creating user")
        return jsonify({"ok": False, "message": "Server error while creating user", "detail": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = safe_get_json()
    if not data:
        return jsonify({"ok": False, "message": "Invalid JSON in request"}), 400
    email = (data.get("email") or "").strip().lower()
    pwd = data.get("password") or ""
    user = users_col.find_one({"email": email})
    if not user or not verify_password(user.get("password_hash"), pwd):
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401
    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

@app.route("/api/google-signin", methods=["POST"])
def google_signin():
    data = safe_get_json() or {}
    id_token_str = data.get("id_token")
    email = None
    if id_token_str:
        try:
            idinfo = google_id_token.verify_oauth2_token(id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID)
            email = idinfo.get("email")
        except Exception as e:
            logging.exception("Invalid Google token")
            return jsonify({"ok": False, "message": "Invalid Google token", "detail": str(e)}), 401
    elif ALLOW_INSECURE_GOOGLE:
        email = (data.get("email") or "").strip().lower()
    else:
        return jsonify({"ok": False, "message": "id_token required"}), 400

    if not email:
        return jsonify({"ok": False, "message": "No email found"}), 400
    create_user_if_missing(email)
    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

# ---------- profile, progress, upload routes (same as your earlier code) ----------
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
    email = get_jwt_identity()
    data = safe_get_json() or {}
    progress_col.update_one(
        {"user_email": email, "module_id": module_id},
        {"$set": {"completed": data.get("completed", []), "scores": data.get("scores", {})}},
        upsert=True
    )
    return jsonify({"ok": True, "message": "Progress saved"})

@app.route("/api/module/<int:module_id>/upload", methods=["POST"])
@jwt_required()
def upload_image(module_id):
    email = get_jwt_identity()
    data = safe_get_json() or {}
    assignment = int(data.get("assignment", 0))
    filename = secure_filename(data.get("filename", "upload.jpg"))
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
    return jsonify({"ok": True, "db": db.name})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
