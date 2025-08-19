import os, re, hashlib, uuid
import filetype
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, jsonify, send_from_directory, abort, flash
)
from flask_socketio import SocketIO, emit

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import ObjectId

import threading
import http.server
import socketserver
from http import HTTPStatus

load_dotenv()

# --- Config ---
FLASK_SECRET = os.getenv("FLASK_SECRET", "dev-secret")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "anon_app")
POST_COOLDOWN_SECONDS = int(os.getenv("POST_COOLDOWN_SECONDS", "120"))
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
MAX_IMAGE_MB = int(os.getenv("MAX_IMAGE_MB", "5"))

Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = FLASK_SECRET

socketio = SocketIO(app, cors_allowed_origins="*")


client = MongoClient(MONGO_URI)
db = client[DB_NAME]
Users = db.users
Posts = db.posts
Banned = db.banned_words
AdminLogs = db.admin_logs

# --- Helpers ---
def get_ip_hash():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "0.0.0.0"
    return hashlib.sha256(ip.encode()).hexdigest()

def ensure_anon_user():
    if "anon_id" not in session:
        # Create or reuse by ip hash (soft)
        tag = f"Student{str(uuid.uuid4())[:8]}"
        user = {
            "anonymous_tag": tag,
            "ip_hash": get_ip_hash(),
            "role": "user",             # user | admin | master_admin
            "status": "active",         # active | banned | muted
            "mute_until": None,         # datetime
            "created_at": datetime.utcnow(),
            "last_post_at": None
        }
        uid = Users.insert_one(user).inserted_id
        session["anon_id"] = str(uid)
        session["anon_tag"] = tag

def current_user():
    if "anon_id" in session:
        return Users.find_one({"_id": ObjectId(session["anon_id"])})
    return None

def is_admin():
    return bool(session.get("admin_id"))

def current_admin():
    if "admin_id" in session:
        return Users.find_one({"_id": ObjectId(session["admin_id"]), "role": {"$in": ["admin", "master_admin"]}})
    return None

def allowed_image(stream, filename):
    if not filename:
        return False
    # size
    stream.seek(0, os.SEEK_END)
    size_mb = stream.tell() / (1024 * 1024)
    stream.seek(0)
    if size_mb > MAX_IMAGE_MB:
        return False
    # extension
    name = secure_filename(filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".gif", ".webp"]:
        return False
    # header detection with filetype
    head = stream.read(261)  # filetype needs at least 261 bytes
    stream.seek(0)
    kind = filetype.guess(head)
    if not kind or not kind.mime.startswith("image/"):
        return False
    return True


def first_boot_seed_admin():
    # Create index & seed initial admin + banned words if needed
    Users.create_index([("role", ASCENDING)])
    Users.create_index([("ip_hash", ASCENDING)])
    Posts.create_index([("created_at", DESCENDING)])
    Posts.create_index([("status", ASCENDING)])
    Banned.create_index([("word", ASCENDING)], unique=True)

    if Users.count_documents({"role": {"$in": ["admin", "master_admin"]}}) == 0:
        email = os.getenv("ADMIN_EMAIL", "admin@local")
        pwd = os.getenv("ADMIN_PASSWORD", "admin123")
        admin = {
            "email": email,
            "password_hash": generate_password_hash(pwd),
            "role": "master_admin",
            "status": "active",
            "anonymous_tag": "AdminRoot",
            "ip_hash": "seed",
            "created_at": datetime.utcnow(),
            "mute_until": None,
            "last_post_at": None
        }
        Users.insert_one(admin)
        print(f"[seed] Created master admin: {email} / (password hidden)")

    if Banned.count_documents({}) == 0:
        defaults = ["slur1", "slur2", "offensiveword", "spamlink.com"]
        for w in defaults:
            try:
                Banned.insert_one({"word": w, "added_at": datetime.utcnow()})
            except:
                pass
        print("[seed] Added default banned words")

@app.before_request
def bootstrap_and_ensure_user():
    first_boot_seed_admin()
    # Do not force anon for static/admin auth calls to avoid recursion
    if request.endpoint not in ("static", "uploads", "admin_login", "admin_logout"):
        ensure_anon_user()

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# --- Views ---
@app.route("/")
def home():
    user = current_user()
    # Get active posts
    posts = list(Posts.find({"status": "active"}).sort("created_at", DESCENDING).limit(100))
    return render_template("index.html", posts=posts, user=user, cooldown=POST_COOLDOWN_SECONDS)

@app.route("/post", methods=["POST"])
def create_post():
    user = current_user()
    if not user:
        abort(401)

    # Check banned or muted
    if user.get("status") == "banned":
        flash("You are banned from posting.", "error")
        return redirect(url_for("home"))

    if user.get("mute_until"):
        if datetime.utcnow() < user["mute_until"]:
            remaining = int((user["mute_until"] - datetime.utcnow()).total_seconds())
            flash(f"You are muted. Try again in {remaining} seconds.", "error")
            return redirect(url_for("home"))
        else:
            Users.update_one({"_id": user["_id"]}, {"$set": {"mute_until": None, "status": "active"}})

    # Cooldown
    last = user.get("last_post_at")
    if last and (datetime.utcnow() - last).total_seconds() < POST_COOLDOWN_SECONDS:
        wait = POST_COOLDOWN_SECONDS - int((datetime.utcnow() - last).total_seconds())
        flash(f"Please wait {wait}s before posting again.", "error")
        return redirect(url_for("home"))

    text = (request.form.get("text") or "").strip()
    image_file = request.files.get("image")
    image_url = None

    # Word filter (case-insensitive, whole-word-ish)
    if text:
        bw = [b["word"] for b in Banned.find({})]
        pattern = r"(" + "|".join([re.escape(w) for w in bw]) + r")" if bw else None
        if pattern and re.search(pattern, text, flags=re.IGNORECASE):
            flash("Your post contains a restricted word.", "error")
            return redirect(url_for("home"))

    # Handle optional image
    if image_file and image_file.filename:
        if not allowed_image(image_file.stream, image_file.filename):
            flash("Invalid or too large image. Allowed: JPG/PNG/GIF/WebP and size <= {}MB".format(MAX_IMAGE_MB), "error")
            return redirect(url_for("home"))

        ext = os.path.splitext(secure_filename(image_file.filename))[1].lower()
        fname = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(UPLOAD_DIR, fname)
        image_file.save(save_path)
        image_url = url_for("uploads", filename=fname)

    if not text and not image_url:
        flash("Post cannot be empty.", "error")
        return redirect(url_for("home"))

    post = {
        "user_id": str(user["_id"]),
        "anonymous_tag": user["anonymous_tag"],
        "text": text if text else None,
        "image_url": image_url,
        "status": "active",  # active | hidden | flagged
        "created_at": datetime.utcnow(),
        "likes": 0
    }
    Posts.insert_one(post)
    Users.update_one({"_id": user["_id"]}, {"$set": {"last_post_at": datetime.utcnow()}})

    flash("Posted! 🎉", "ok")
    return redirect(url_for("home"))

@app.route("/like/<post_id>", methods=["POST"])
def like(post_id):
    user = current_user()
    if not user:
        abort(401)

    post = Posts.find_one({"_id": ObjectId(post_id), "status": "active"})
    if not post:
        abort(404)

    user_id = str(user["_id"])

    if user_id in post.get("liked_by", []):
        # Already liked → unlike
        Posts.update_one(
            {"_id": ObjectId(post_id)},
            {
                "$inc": {"likes": -1},
                "$pull": {"liked_by": user_id}
            }
        )
        new_likes = max(post["likes"] - 1, 0)  # Prevent negatives
        action = "unliked"
    else:
        # Not liked yet → like
        Posts.update_one(
            {"_id": ObjectId(post_id)},
            {
                "$inc": {"likes": 1},
                "$push": {"liked_by": user_id}
            }
        )
        new_likes = post["likes"] + 1
        action = "liked"

    # Broadcast updated like count
    socketio.emit("like_update", {
        "post_id": post_id,
        "likes": new_likes,
        "user_id": user_id,
        "action": action
    }, broadcast=True)

    return jsonify({"likes": new_likes, "action": action})



# --- Admin Auth ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")
    email = request.form.get("email", "").strip().lower()
    pwd = request.form.get("password", "")
    admin = Users.find_one({"email": email, "role": {"$in": ["admin", "master_admin"]}})
    if not admin or not check_password_hash(admin.get("password_hash", ""), pwd):
        flash("Invalid credentials.", "error")
        return redirect(url_for("admin_login"))
    session["admin_id"] = str(admin["_id"])
    flash("Welcome, admin.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    if "admin_id" in session:
        session.pop("admin_id")
    flash("Logged out.", "ok")
    return redirect(url_for("home"))

# --- Admin Dashboard & Actions ---
@app.route("/admin")
def admin_dashboard():
    admin = current_admin()
    if not admin:
        return redirect(url_for("admin_login"))
    posts = list(Posts.find({}).sort("created_at", DESCENDING).limit(200))
    users = list(Users.find({}).sort("created_at", DESCENDING).limit(200))
    banned = list(Banned.find({}).sort("word", ASCENDING))
    return render_template("admin.html", posts=posts, users=users, banned=banned, admin=admin)

def log_admin(action, target=None, extra=None):
    ad = current_admin()
    AdminLogs.insert_one({
        "admin_id": str(ad["_id"]) if ad else None,
        "action": action,
        "target": target,
        "extra": extra,
        "at": datetime.utcnow()
    })

@app.post("/admin/hide_post")
def admin_hide_post():
    if not current_admin(): abort(403)
    pid = request.form.get("post_id")
    Posts.update_one({"_id": ObjectId(pid)}, {"$set": {"status": "hidden"}})
    log_admin("hide_post", target=pid)
    flash("Post hidden.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/ban_user")
def admin_ban_user():
    if not current_admin(): abort(403)
    uid = request.form.get("user_id")
    Users.update_one({"_id": ObjectId(uid)}, {"$set": {"status": "banned"}})
    log_admin("ban_user", target=uid)
    flash("User banned.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/mute_user")
def admin_mute_user():
    if not current_admin(): abort(403)
    uid = request.form.get("user_id")
    minutes = int(request.form.get("minutes", "10"))
    until = datetime.utcnow() + timedelta(minutes=minutes)
    Users.update_one({"_id": ObjectId(uid)}, {"$set": {"status": "muted", "mute_until": until}})
    log_admin("mute_user", target=uid, extra={"minutes": minutes})
    flash(f"User muted for {minutes} minutes.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/promote_admin")
def admin_promote():
    admin = current_admin()
    if not admin or admin["role"] not in ["admin", "master_admin"]:
        abort(403)
    uid = request.form.get("user_id")
    role_to = request.form.get("role", "admin")
    if role_to == "master_admin" and admin["role"] != "master_admin":
        flash("Only master admin can create another master admin.", "error")
        return redirect(url_for("admin_dashboard"))
    Users.update_one({"_id": ObjectId(uid)}, {"$set": {"role": role_to}})
    log_admin("promote_admin", target=uid, extra={"role": role_to})
    flash("Role updated.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/add_banned_word")
def admin_add_banned():
    if not current_admin(): abort(403)
    word = request.form.get("word", "").strip().lower()
    if not word:
        flash("Word cannot be empty.", "error")
        return redirect(url_for("admin_dashboard"))
    try:
        Banned.insert_one({"word": word, "added_at": datetime.utcnow()})
        log_admin("add_banned_word", extra={"word": word})
        flash("Word added.", "ok")
    except:
        flash("Word already exists.", "error")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/remove_banned_word")
def admin_remove_banned():
    if not current_admin(): abort(403)
    wid = request.form.get("word_id")
    Banned.delete_one({"_id": ObjectId(wid)})
    log_admin("remove_banned_word", target=wid)
    flash("Word removed.", "ok")
    return redirect(url_for("admin_dashboard"))

# --- Error pages minimal ---
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Not Found"), 404

#PORT = 8080

#class Handler(http.server.SimpleHTTPRequestHandler):
 #   def do_GET(self):
  #      self.send_response(HTTPStatus.OK)
   #     self.end_headers()
    #    self.wfile.write(b'Hello World!')

#def run_raw_server():
 #   with socketserver.TCPServer(("", PORT), Handler) as httpd:
  #      httpd.allow_reuse_address = True
   #     print("Raw HTTP server started at port", PORT)
    #    httpd.serve_forever()


# ------------------ Main Entry ------------------
if __name__ == "__main__":
    # Use the port Koyeb provides (default 8080), fallback to 5000 locally
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)


