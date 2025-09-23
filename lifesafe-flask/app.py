# app.py
import os
import base64
from datetime import timedelta
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING
from passlib.hash import bcrypt
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity
)
from bson.objectid import ObjectId

load_dotenv()

MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is required. Set it in your .env file.")

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-me")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "admin-secret")

app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=6)

jwt = JWTManager(app)

# Mongo client
client = MongoClient(MONGO_URI)
db = client.get_default_database()  # uses DB from connection string (e.g. 'lifesafe')
users_col = db["users"]
profiles_col = db["profiles"]
progress_col = db["module_progress"]  # store per-user per-module progress
images_col = db["uploads"]

# Indexes for quick lookup
users_col.create_index([("email", ASCENDING)], unique=True)
profiles_col.create_index([("idNo", ASCENDING)], unique=True, sparse=True)
progress_col.create_index([("user_email", ASCENDING), ("module_id", ASCENDING)], unique=True, sparse=True)

# --- Helpers ---
def hash_password(raw: str) -> str:
    return bcrypt.hash(raw)

def verify_password(hash_, raw: str) -> bool:
    try:
        return bcrypt.verify(raw, hash_)
    except Exception:
        return False

def user_public(user_doc, profile_doc=None):
    p = profile_doc or profiles_col.find_one({"user_email": user_doc["email"]})
    return {
        "email": user_doc["email"],
        "createdAt": user_doc.get("createdAt"),
        "studentName": p.get("studentName") if p else "",
        "dob": p.get("dob") if p else None,
        "idNo": p.get("idNo") if p else None,
        "school": p.get("school") if p else "",
        "father": p.get("father") if p else "",
        "contact": p.get("contact") if p else "",
        "emergency": p.get("emergency") if p else "",
    }

# --- Routes ---

@app.route("/api/register", methods=["POST"])
def register():
    """
    JSON:
    {
      studentName, dob (YYYY-MM-DD), idNo, school, father, contact, emergency, email, password
    }
    """
    data = request.get_json(force=True)
    required = ["studentName", "idNo", "email", "password"]
    for r in required:
        if not data.get(r):
            return jsonify({"ok": False, "message": f"{r} is required"}), 400

    email = data["email"].strip().lower()
    if users_col.find_one({"email": email}):
        return jsonify({"ok": False, "message": "Email already registered"}), 400
    if data.get("idNo") and profiles_col.find_one({"idNo": data["idNo"]}):
        return jsonify({"ok": False, "message": "ID/Aadhar already registered"}), 400

    user_doc = {
        "email": email,
        "password_hash": hash_password(data["password"]),
        "createdAt": None
    }
    users_col.insert_one(user_doc)

    profile_doc = {
        "user_email": email,
        "studentName": data.get("studentName"),
        "dob": data.get("dob"),
        "idNo": data.get("idNo"),
        "school": data.get("school"),
        "father": data.get("father"),
        "contact": data.get("contact"),
        "emergency": data.get("emergency"),
        "xp": 0
    }
    profiles_col.insert_one(profile_doc)

    token = create_access_token(identity=email)
    return jsonify({"ok": True, "message": "Registered", "access": token}), 201

@app.route("/api/login", methods=["POST"])
def login():
    """
    { email, password }
    """
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    pwd = data.get("password") or ""
    if not email or not pwd:
        return jsonify({"ok": False, "message": "Email and password required"}), 400

    user = users_col.find_one({"email": email})
    if not user or not user.get("password_hash"):
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401
    if not verify_password(user["password_hash"], pwd):
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401

    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

@app.route("/api/google-signin", methods=["POST"])
def google_signin():
    """
    Demo flow: accepts {"email": "..."} OR {"id_token": "..."} if you later verify with Google.
    Server will create user if missing (password_hash = None).
    """
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "message": "Email required"}), 400

    user = users_col.find_one({"email": email})
    if not user:
        users_col.insert_one({"email": email, "password_hash": None})
        profiles_col.insert_one({"user_email": email, "studentName": email.split("@")[0], "xp": 0})
    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    email = get_jwt_identity()
    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"ok": False, "message": "User not found"}), 404
    profile_doc = profiles_col.find_one({"user_email": email}) or {}
    return jsonify({"ok": True, "profile": user_public(user, profile_doc)})

# Module progress endpoints (module_id is integer)
@app.route("/api/module/<int:module_id>/progress", methods=["GET"])
@jwt_required()
def get_module_progress(module_id):
    email = get_jwt_identity()
    doc = progress_col.find_one({"user_email": email, "module_id": module_id})
    if not doc:
        # Return empty progress with default structure
        return jsonify({"ok": True, "completed": [], "scores": {}, "uploads": []})
    # ensure JSON serializable
    return jsonify({
        "ok": True,
        "completed": doc.get("completed", []),
        "scores": doc.get("scores", {}),
        "uploads": doc.get("uploads", [])  # list of upload metadata (ids, filenames)
    })

@app.route("/api/module/<int:module_id>/progress", methods=["POST"])
@jwt_required()
def save_module_progress(module_id):
    """
    Expect JSON:
    {
      completed: [1,2,3],
      scores: { "1": 8, "2": 10, ... }   # numeric scores per assignment
    }
    """
    email = get_jwt_identity()
    data = request.get_json(force=True) or {}
    completed = data.get("completed", [])
    scores = data.get("scores", {})
    # Upsert
    progress_col.update_one(
        {"user_email": email, "module_id": module_id},
        {"$set": {"completed": completed, "scores": scores}},
        upsert=True
    )
    return jsonify({"ok": True, "message": "Progress saved"})

@app.route("/api/module/<int:module_id>/upload", methods=["POST"])
@jwt_required()
def upload_image(module_id):
    """
    Accepts JSON:
    {
      "assignment": 4,
      "filename": "photo.jpg",
      "b64": "<base64 data URI or raw base64>"
    }
    Saves in 'uploads' collection and links to module progress document.
    """
    email = get_jwt_identity()
    data = request.get_json(force=True) or {}
    assignment = int(data.get("assignment", 0))
    filename = data.get("filename", "upload.jpg")
    b64 = data.get("b64")
    if not b64:
        return jsonify({"ok": False, "message": "No image data provided"}), 400

    # Accept either "data:image/png;base64,AAAA..." or raw base64
    if b64.startswith("data:"):
        try:
            header, bdata = b64.split(",", 1)
        except ValueError:
            return jsonify({"ok": False, "message": "Invalid data URI"}), 400
    else:
        bdata = b64

    try:
        # decode to ensure well-formed
        binary = base64.b64decode(bdata, validate=True)
    except Exception as e:
        return jsonify({"ok": False, "message": "Invalid base64 data"}), 400

    # store as base64 string in DB (ok for prototypes). Add metadata.
    upload_doc = {
        "user_email": email,
        "module_id": module_id,
        "assignment": assignment,
        "filename": filename,
        "b64": bdata,  # store base64
        "size": len(binary),
    }
    res = images_col.insert_one(upload_doc)
    upload_id = str(res.inserted_id)

    # link upload id to progress doc
    progress_col.update_one(
        {"user_email": email, "module_id": module_id},
        {"$push": {"uploads": {"upload_id": upload_id, "assignment": assignment, "filename": filename}}},
        upsert=True
    )

    return jsonify({"ok": True, "upload_id": upload_id})

# Admin route (very simple) to list users - protected by ADMIN_SECRET header
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

# Simple healthcheck
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "db": db.name})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)