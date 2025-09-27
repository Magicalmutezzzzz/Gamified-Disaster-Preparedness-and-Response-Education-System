#!/usr/bin/env python3
"""
app.py
Single-file Flask backend for Gamified Disaster Preparedness & Response Education System.

Note: set environment variables (MONGO_URI, JWT_SECRET_KEY, ADMIN_SECRET, etc.)
"""

import os
import base64
import binascii
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING
from passlib.hash import bcrypt
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
)
from werkzeug.utils import secure_filename

# Optional Google verification libs
try:
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_LIBS_AVAILABLE = True
except Exception:
    GOOGLE_LIBS_AVAILABLE = False

# Load .env if present
load_dotenv()

# ---------------------------
# Environment variables
# ---------------------------
MONGO_URI = os.environ.get("MONGO_URI")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "*")
ALLOW_INSECURE_GOOGLE = os.environ.get("ALLOW_INSECURE_GOOGLE", "0") == "1"

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is required in environment")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is required in environment")
if not ADMIN_SECRET:
    raise RuntimeError("ADMIN_SECRET is required in environment")

# ---------------------------
# Flask app
# ---------------------------
app = Flask(__name__, static_folder="frontend", static_url_path="/")
# allow wildcard or single origin
if FRONTEND_ORIGIN == "*" or FRONTEND_ORIGIN == "":
    CORS(app)
else:
    CORS(app, resources={r"/*": {"origins": FRONTEND_ORIGIN}})

app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=6)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", 5)) * 1024 * 1024

jwt = JWTManager(app)

# ---------------------------
# MongoDB
# ---------------------------
client = MongoClient(MONGO_URI)
db = client.get_default_database()

users_col = db["users"]
profiles_col = db["profiles"]
progress_col = db["module_progress"]
images_col = db["uploads"]
modules_col = db["modules"]

# Ensure indexes
users_col.create_index([("email", ASCENDING)], unique=True)
profiles_col.create_index([("idNo", ASCENDING)], unique=True, sparse=True)
progress_col.create_index([("user_email", ASCENDING), ("module_id", ASCENDING)], unique=True, sparse=True)
modules_col.create_index([("module_id", ASCENDING)], unique=True, sparse=True)

# ---------------------------
# Helpers
# ---------------------------
def hash_password(raw: str) -> str:
    return bcrypt.hash(raw)

def verify_password(hash_, raw: str) -> bool:
    try:
        if not hash_:
            return False
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
        "xp": p.get("xp", 0)
    }

def decode_base64_image(b64str):
    if not b64str:
        return None, "No data"
    if "," in b64str:
        b64str = b64str.split(",", 1)[1]
    try:
        binary = base64.b64decode(b64str, validate=True)
        return binary, None
    except (binascii.Error, ValueError):
        return None, "Invalid base64 data"

def create_user_if_missing(email):
    email = (email or "").strip().lower()
    if not email:
        return
    if not users_col.find_one({"email": email}):
        users_col.insert_one({"email": email, "password_hash": None})
        profiles_col.insert_one({"user_email": email, "studentName": email.split("@")[0], "xp": 0})

def sanitize_quiz_for_client(assignment_doc):
    doc = dict(assignment_doc)
    if doc.get("type") == "quiz" and isinstance(doc.get("quiz"), dict):
        quiz = dict(doc["quiz"])
        safe_qs = []
        for q in quiz.get("questions", []):
            qq = dict(q)
            qq.pop("answer", None)
            safe_qs.append(qq)
        quiz["questions"] = safe_qs
        doc["quiz"] = quiz
    return doc

def grade_quiz(assignment_doc, answers):
    quiz = assignment_doc.get("quiz", {}) or {}
    questions = quiz.get("questions", []) or []
    score = 0
    total = len(questions)
    detail = []
    for i, q in enumerate(questions):
        correct = q.get("answer")
        submitted = None
        if isinstance(answers, dict):
            submitted = answers.get(str(i), answers.get(i))
        elif isinstance(answers, (list, tuple)):
            if i < len(answers):
                submitted = answers[i]
        try:
            ok = (submitted is not None and int(submitted) == int(correct))
        except Exception:
            ok = False
        if ok:
            score += 1
        detail.append({"q_index": i, "submitted": submitted, "correct": correct, "ok": ok})
    return {"score": score, "total": total, "detail": detail}

# ---------------------------
# Static routes
# ---------------------------
@app.route("/")
def index():
    try:
        return app.send_static_file("index.html")
    except Exception:
        return jsonify({"ok": True, "message": "Backend running. No static frontend deployed."})

@app.route("/<path:p>")
def static_proxy(p):
    try:
        return app.send_static_file(p)
    except Exception:
        return jsonify({"ok": False, "message": "Not found"}), 404

# ---------------------------
# Auth
# ---------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True) or {}
    required = ["studentName", "idNo", "email", "password"]
    for r in required:
        if not data.get(r):
            return jsonify({"ok": False, "message": f"{r} is required"}), 400
    email = data["email"].strip().lower()
    if users_col.find_one({"email": email}):
        return jsonify({"ok": False, "message": "Email already registered"}), 400
    if data.get("idNo") and profiles_col.find_one({"idNo": data["idNo"]}):
        return jsonify({"ok": False, "message": "ID/Aadhar already registered"}), 400

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

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    pwd = data.get("password") or ""
    user = users_col.find_one({"email": email})
    if not user or not verify_password(user.get("password_hash"), pwd):
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401
    token = create_access_token(identity=email)
    return jsonify({"ok": True, "access": token})

@app.route("/api/google-signin", methods=["POST"])
def google_signin():
    data = request.get_json(force=True) or {}
    id_token_str = data.get("id_token")
    email = None

    if id_token_str:
        if not GOOGLE_LIBS_AVAILABLE:
            return jsonify({"ok": False, "message": "Google libraries not installed on server"}), 500
        try:
            idinfo = google_id_token.verify_oauth2_token(id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID)
            email = idinfo.get("email")
        except Exception as e:
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

# ---------------------------
# Profile & progress
# ---------------------------
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
    data = request.get_json(force=True) or {}
    progress_col.update_one(
        {"user_email": email, "module_id": module_id},
        {"$set": {"completed": data.get("completed", []), "scores": data.get("scores", {})}},
        upsert=True
    )
    return jsonify({"ok": True, "message": "Progress saved"})

# ---------------------------
# Module content (public)
# ---------------------------
@app.route("/api/modules", methods=["GET"])
def list_modules():
    modules = []
    for m in modules_col.find({}, {"_id": 0}):
        mod = dict(m)
        safe_assignments = [sanitize_quiz_for_client(a) for a in mod.get("assignments", [])]
        mod["assignments"] = safe_assignments
        modules.append(mod)
    return jsonify({"ok": True, "modules": modules})

@app.route("/api/module/<int:module_id>", methods=["GET"])
def get_module(module_id):
    m = modules_col.find_one({"module_id": module_id}, {"_id": 0})
    if not m:
        return jsonify({"ok": False, "message": "Module not found"}), 404
    m["assignments"] = [sanitize_quiz_for_client(a) for a in m.get("assignments", [])]
    return jsonify({"ok": True, "module": m})

@app.route("/api/module/<int:module_id>/assignment/<int:assignment_no>", methods=["GET"])
def get_assignment(module_id, assignment_no):
    # allow optional JWT
    try:
        verify_jwt_in_request(optional=True)
    except TypeError:
        try:
            verify_jwt_in_request()
        except Exception:
            pass
    except Exception:
        pass

    m = modules_col.find_one({"module_id": module_id}, {"_id": 0})
    if not m:
        return jsonify({"ok": False, "message": "Module not found"}), 404
    a_doc = next((a for a in m.get("assignments", []) if int(a.get("assignment")) == assignment_no), None)
    if not a_doc:
        return jsonify({"ok": False, "message": "Assignment not found"}), 404
    return jsonify({"ok": True, "assignment": sanitize_quiz_for_client(a_doc), "module_meta": {"module_id": module_id, "title": m.get("title")}})

# ---------------------------
# Submit quiz (authenticated)
# ---------------------------
@app.route("/api/module/<int:module_id>/assignment/<int:assignment_no>/submit", methods=["POST"])
@jwt_required()
def submit_assignment(module_id, assignment_no):
    email = get_jwt_identity()
    data = request.get_json(force=True) or {}
    answers = data.get("answers")
    if answers is None:
        return jsonify({"ok": False, "message": "answers required"}), 400

    m = modules_col.find_one({"module_id": module_id})
    if not m:
        return jsonify({"ok": False, "message": "Module not found"}), 404

    a_doc = next((a for a in m.get("assignments", []) if int(a.get("assignment")) == assignment_no), None)
    if not a_doc:
        return jsonify({"ok": False, "message": "Assignment not found"}), 404

    if a_doc.get("type") != "quiz":
        return jsonify({"ok": False, "message": "This assignment does not accept quiz submissions"}), 400

    result = grade_quiz(a_doc, answers)
    score = int(result["score"])
    total = int(result["total"])

    prog = progress_col.find_one({"user_email": email, "module_id": module_id}) or {"user_email": email, "module_id": module_id, "completed": [], "scores": {}, "uploads": []}
    completed = set(prog.get("completed", []))
    completed.add(assignment_no)
    scores = prog.get("scores", {})
    scores[str(assignment_no)] = score
    progress_col.update_one({"user_email": email, "module_id": module_id}, {"$set": {"completed": list(completed), "scores": scores}}, upsert=True)

    profiles_col.update_one({"user_email": email}, {"$inc": {"xp": score}}, upsert=True)

    return jsonify({"ok": True, "result": result, "score": score, "total": total})

# ---------------------------
# Upload (image) for assignments
# ---------------------------
@app.route("/api/module/<int:module_id>/upload", methods=["POST"])
@jwt_required()
def upload_image(module_id):
    email = get_jwt_identity()
    data = request.get_json(force=True) or {}
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

# ---------------------------
# Admin: users & bootstrap
# ---------------------------
@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    secret = request.headers.get("X-Admin-Secret")
    if secret != ADMIN_SECRET:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    users = []
    for u in users_col.find({}, {"password_hash": 0, "_id": 0}):
        profile = profiles_col.find_one({"user_email": u["email"]}, {"_id": 0}) or {}
        progress = list(progress_col.find({"user_email": u["email"]}, {"_id": 0}))
        users.append({"email": u["email"], "profile": profile, "progress": progress})
    return jsonify({"ok": True, "users": users})

@app.route("/api/admin/bootstrap", methods=["POST"])
def admin_bootstrap():
    secret = request.headers.get("X-Admin-Secret")
    if secret != ADMIN_SECRET:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    data = request.get_json(force=True) or {}
    mode = (data.get("mode") or "merge").lower()
    modules = data.get("modules", [])
    if not isinstance(modules, list):
        return jsonify({"ok": False, "message": "modules must be a list"}), 400

    upserted = 0
    try:
        if mode == "replace":
            modules_col.delete_many({})
        for m in modules:
            if "module_id" not in m:
                continue
            module_id = int(m["module_id"])
            m["module_id"] = module_id
            m["assignments"] = m.get("assignments", [])
            for a in m["assignments"]:
                a["assignment"] = int(a.get("assignment", 0))
                a["type"] = a.get("type", "quiz")
                if a["type"] == "quiz":
                    a["quiz"] = a.get("quiz", {"questions": []})
                    for q in a["quiz"].get("questions", []):
                        q["q"] = q.get("q", "")
                        q["options"] = q.get("options", [])
                        if "answer" in q:
                            try:
                                q["answer"] = int(q["answer"])
                            except Exception:
                                q.pop("answer", None)
            modules_col.update_one({"module_id": module_id}, {"$set": m}, upsert=True)
            upserted += 1
    except Exception as e:
        return jsonify({"ok": False, "message": "Bootstrap failed", "detail": str(e)}), 500
    return jsonify({"ok": True, "mode": mode, "upserted": upserted})

# ---------------------------
# Health
# ---------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "db": db.name})

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
