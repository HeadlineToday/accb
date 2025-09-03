import os, re, hashlib, uuid
import filetype
import random
from supabase import create_client, Client
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, jsonify, abort, flash
)
from flask_socketio import SocketIO, emit

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import ObjectId
from bson.errors import InvalidId


load_dotenv()

# --- Config ---
FLASK_SECRET = os.getenv("FLASK_SECRET", "dev-secret")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "anon_app")
POST_COOLDOWN_SECONDS = int(os.getenv("POST_COOLDOWN_SECONDS", "120"))


MAX_IMAGE_MB = int(os.getenv("MAX_IMAGE_MB", "5"))


app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("SECRET_KEY", "fallback")
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "uploads")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)



client = MongoClient(MONGO_URI)
db = client[DB_NAME]
Users = db.users
Posts = db.posts
Banned = db.banned_words
AdminLogs = db.admin_logs
posts_collection = db["posts"]
Comments = db.comments



NAMES = [
      "Med-", "Rx-", "Dx-", "Tx-", "Hx-", "Px-", "Ax-", "Lab-", "Scan-", "Case-", "Note-", "Path-", "Neuro-", "Cardio-", "Surg-", "Ortho-", "Onco-", "Oto-", "Ophtho-", "Uro-", "Gastro-",
    "Hema-", "Pharma-", "Toxo-", "Micro-", "Bio-", "Viva-", "Prep-", "Quiz-", "Ward-", "Bed-", "Rounds-", "Pulse-", "Scope-", "Tube-", "Cell-", "Gene-", "Code-", "Stat-", 
    "Chart-", "File-", "Doc-", "MBBS-", "MedX-", "Diag-", "Echo-", "Xray-", "Spec-", "PathX-", "NoteX-", "CaseX-", "ExamX-", "RxBox-", "LabX-", "ScanX-", "Neo-", "Core-", 
    "Anato-", "Histo-", "Cyt-", "Derm-", "Nephro-", "Pulmo-", "Hepato-", "Mentor-", "Tutor-", "Anony-", "Medz-", "Clini-", "Aid-", "Cura-", "Script-", "Atlas-", "Board-", 
    "Chain-", "Track-", "Gen-", "Net-", "Flow-", "Sphere-", "Bridge-", "Vault-", "Loop-", "Link-", "Step-", "Gram-", "Byte-", "CellX-", "WardX-", "PulseX-", "Mind-", "Brain-", 
    "Cortex-", "Stetho-", "Suture-", "Vitals-", "Examz-", "Skill-", "TutorX-", "CaseHub-", "PathHub-", "EchoX-", "NeuroX-", "CardX-", "ScanHub-", "NoteHub-", "CoreX-", "DocX-", 
    "QuickX-", "StudyX-", "Wardz-", "Pulsez-", "PrepX-", "TrackX-", "NeoX-", "AnonyX-", "MedHub-", "RxHub-", "DxHub-", "TxHub-", "BioX-", "GeneX-"
]

# --- Helpers ---
def get_ip_hash():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "0.0.0.0"
    return hashlib.sha256(ip.encode()).hexdigest()

def ensure_anon_user(): 
    if "anon_id" not in session:
        # Pick a random name from the list
        base_name = random.choice(NAMES)
        tag = f"{base_name}{str(uuid.uuid4())[:3]}"  # shorter suffix for neatness
        
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
    Comments.create_index([("post_id", ASCENDING), ("created_at", DESCENDING)])
    Comments.create_index([("parent_id", ASCENDING)])

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



@app.route("/search")
def search_posts():
    query = request.args.get("q", "").strip()
    if not query:
        return redirect(url_for("home"))

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    regex = re.escape(query)

    # pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    skip = (page - 1) * per_page

    filter_query = {
        "text": {"$regex": regex, "$options": "i"},
        "status": "active",
        "created_at": {"$gte": cutoff}
    }

    cursor = Posts.find(filter_query).sort("created_at", -1)
    total_results = Posts.count_documents(filter_query)  # ✅ correct way now
    results = list(cursor.skip(skip).limit(per_page))

    total_pages = (total_results + per_page - 1) // per_page

    return render_template(
        "search_results.html",
        results=results,
        query=query,
        page=page,
        total_pages=total_pages,
        per_page=per_page
    )







# --- Views ---
@app.route("/")
def home():
    user = current_user()
    posts = list(Posts.find({"status": "active"}).sort("created_at", DESCENDING).limit(100))
    for p in posts:
        p["comment_count"] = p.get("comment_count", 0)   # ensure it’s there
    return render_template("index.html", posts=posts, user=user, cooldown=POST_COOLDOWN_SECONDS)

@app.route("/api/comment_counts")
def comment_counts():
    counts = {}
    for p in Posts.find({}, {"_id": 1, "comment_count": 1}):
        counts[str(p["_id"])] = p.get("comment_count", 0)
    return jsonify(counts)

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
        file_bytes = image_file.read()
        supabase.storage.from_(SUPABASE_BUCKET).upload(
            f"posts/{fname}", file_bytes, {"content-type": image_file.mimetype})
        image_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/posts/{fname}"


    if not text and not image_url:
        flash("Post cannot be empty.", "error")
        return redirect(url_for("home"))

    # Build the doc
    post = {
        "user_id": str(user["_id"]),
        "anonymous_tag": user["anonymous_tag"],
        "text": text if text else None,
        "image_url": image_url,
        "status": "active",
        "created_at": datetime.utcnow(),
        "likes": 0,
        "liked_by": []
    }
    
    # Insert & capture the new _id
   # --- inside create_post() right after insert_one ---

    res = Posts.insert_one(post)
    post_id = str(res.inserted_id)
    
    Users.update_one({"_id": user["_id"]}, {"$set": {"last_post_at": datetime.utcnow()}})
    
    # 🔥 Broadcast the new post to everyone (include _id and status)
    socketio.emit("new_post", {
        "_id": post_id,                       # <— add
        "post_id": post_id,                   # keep alias if you already use it
        "anonymous_tag": post["anonymous_tag"],
        "text": post["text"],
        "image_url": post["image_url"],
        "created_at": post["created_at"].isoformat(),
        "status": "active",                   # <— add
        "likes": post["likes"],
    })

    
    flash("Posted! 🎉", "ok")
    return redirect(url_for("home"))


@app.route("/like/<post_id>", methods=["POST"])
def like(post_id):
    user = current_user()
    if not user:
        abort(401)

        # Stop banned or muted users
    if user.get("status") == "banned":
        return jsonify({"success": False, "error": "Action not allowed"}), 403

    mute_until = user.get("mute_until")
    if mute_until and mute_until > datetime.utcnow():
        return jsonify({"success": False, "error": "Action not allowed"}), 403


    post = Posts.find_one({"_id": ObjectId(post_id), "status": "active"})
    if not post:
        abort(404)

    user_id = str(user["_id"])
    current_likes = int(post.get("likes", 0))
    liked_by = post.get("liked_by", [])

    # Toggle like
    if user_id in liked_by:
        # Unlike
        Posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$inc": {"likes": -1}, "$pull": {"liked_by": user_id}}
        )
        new_likes = max(current_likes - 1, 0)
        liked = False
    else:
        # Like
        Posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$inc": {"likes": 1}, "$push": {"liked_by": user_id}}
        )
        new_likes = current_likes + 1
        liked = True

    # Broadcast to everyone: only the counts
    socketio.emit(
        "like_update",
        {
            "post_id": post_id,
            "likes": new_likes,
            "user_id": user_id,
            "user_tag": user.get("anonymous_tag"),
        }
    )
    
    # Send liked/unliked state only to the current user (via HTTP response)
    return jsonify({"likes": new_likes, "liked": liked})

# --- Comment ---

def _get_post_or_404(post_id):
    try:
        oid = ObjectId(post_id)
    except (InvalidId, TypeError):
        abort(404)
    post = Posts.find_one({"_id": oid})
    if not post:
        abort(404)
    return post, oid

def _build_comment_tree(raw_comments):
    """Turn a flat list into {top_level: [...], replies under each}."""
    by_id = {str(c["_id"]): c for c in raw_comments}
    for c in raw_comments:
        c["_id"] = str(c["_id"])
        pid = c.get("parent_id")
        c["replies"] = []
        if pid is not None:
            c["parent_id"] = str(pid)
            
        # ✅ Add avatar_url for each comment based on tag
        tag = c.get("anonymous_tag", "Anon")
        c["avatar_url"] = f"https://api.dicebear.com/9.x/thumbs/svg?seed={tag}"

    roots = []
    for c in raw_comments:
        if c.get("parent_id"):
            parent = by_id.get(c["parent_id"])
            if parent:
                parent["replies"].append(c)
        else:
            roots.append(c)
    # sort children by created_at ascending (oldest first)
    def _sort_branch(node):
        node["replies"].sort(key=lambda x: x["created_at"])
        for r in node["replies"]:
            _sort_branch(r)
    for r in roots:
        _sort_branch(r)
    # final sort roots too
    roots.sort(key=lambda x: x["created_at"])
    return roots





# === Comment Page (view) ===
@app.route("/post/<post_id>/comments", methods=["GET"])
def view_comments(post_id):
    user = current_user()
    post, post_oid = _get_post_or_404(post_id)

    raw = list(
        Comments.find({"post_id": post_oid})
        .sort("created_at", ASCENDING)
    )
    comments = _build_comment_tree(raw)

    return render_template(
        "comments.html",
        post=post,
        comments=comments,
        user=user
    )

# === Add Comment or Reply (same endpoint; parent_id optional) ===
@app.post("/post/<post_id>/comments")
def add_comment(post_id):
    user = current_user()
    if not user:
        abort(401)
    if user.get("status") in ("banned",):
        flash("Action not allowed.", "error")
        return redirect(url_for("view_comments", post_id=post_id))

    post, post_oid = _get_post_or_404(post_id)

    text = (request.form.get("text") or "").strip()
    if not text:
        flash("Comment cannot be empty.", "error")
        return redirect(url_for("view_comments", post_id=post_id))

    parent_id_raw = request.form.get("parent_id")
    parent_oid = None
    if parent_id_raw:
        try:
            parent_oid = ObjectId(parent_id_raw)
            parent_comment = Comments.find_one({"_id": parent_oid})
            if parent_comment and parent_comment.get("parent_id"):
                parent_oid = parent_comment["parent_id"]
        except (InvalidId, TypeError):
            parent_oid = None

    doc = {
        "post_id": post_oid,
        "user_id": str(user["_id"]),
        "anonymous_tag": user.get("anonymous_tag"),
        "text": text,
        "parent_id": parent_oid,
        "created_at": datetime.utcnow(),
    }
    res = Comments.insert_one(doc)
    comment_id = str(res.inserted_id)

    # increment post counter
    # increment post counter only for top-level comments
    if parent_oid is None:
        Posts.update_one({"_id": post_oid}, {"$inc": {"comment_count": 1}})
    new_count = Posts.find_one({"_id": post_oid}).get("comment_count", 0)



    # broadcast live
    socketio.emit("new_comment", {
        "post_id": str(post_oid),
        "comment_id": comment_id,
        "anonymous_tag": user.get("anonymous_tag"),
        "text": text,
        "created_at": doc["created_at"].isoformat(),
        "parent_id": str(parent_oid) if parent_oid else None,
        "comment_count": new_count,
    })

    return redirect(url_for("view_comments", post_id=post_id))






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

    # Users sorted by most recent post or creation
    users = list(
        Users.find({})
        .sort([("last_post_at", DESCENDING), ("created_at", DESCENDING)])
        .limit(200)
    )

    banned = list(Banned.find({}).sort("word", ASCENDING))
    return render_template(
        "admin.html",
        posts=posts,
        users=users,
        banned=banned,
        admin=admin,
        now=datetime.utcnow()
    )


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

    # Broadcast to ALL clients so UIs update without refresh
    socketio.emit("post_status_changed", {"post_id": pid, "status": "hidden"})
    # Fallback for form submit: keep your flash+redirect behaviour
    flash("Post hidden.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/unhide_post")
def admin_unhide_post():
    if not current_admin(): abort(403)
    pid = request.form.get("post_id")
    Posts.update_one({"_id": ObjectId(pid)}, {"$set": {"status": "active"}})
    log_admin("unhide_post", target=pid)

    # Broadcast to ALL clients so UIs update without refresh
    socketio.emit("post_status_changed", {"post_id": pid, "status": "active"})
    # Fallback for form submit: keep your flash+redirect behaviour
    flash("Post unhidden.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.route("/delete/<post_id>", methods=["POST"])
def delete_post(post_id):
    if not current_admin():
        abort(403)

    post = Posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        abort(404)

    image_url = post.get("image_url")
    if image_url:
        try:
            file_path = image_url.split("/posts/")[-1]
            supabase.storage.from_(SUPABASE_BUCKET).remove([f"posts/{file_path}"])
            app.logger.info(f"Deleting file from Supabase: posts/{file_path}")
        except Exception as e:
            app.logger.error(f"Failed to delete image from Supabase: {e}")

    result = Posts.delete_one({"_id": ObjectId(post_id)})
    if result.deleted_count == 0:
        abort(404)

    # 🔊 broadcast so all clients (feed + admin) remove it live
    socketio.emit("post_deleted", {"post_id": post_id})

    # If the caller expects JSON (AJAX), return JSON; otherwise normal redirect
    wants_json = "application/json" in (request.headers.get("Accept") or "")
    if wants_json:
        return jsonify({"success": True})
    flash("Post deleted successfully!", "success")
    return redirect(url_for("admin_dashboard"))







@app.post("/admin/ban_user")
def admin_ban_user():
    if not current_admin(): abort(403)
    uid = request.form.get("user_id")
    Users.update_one({"_id": ObjectId(uid)}, {"$set": {"status": "banned"}})
    log_admin("ban_user", target=uid)
    flash("User banned.", "ok")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/unban_user", methods=["POST"])
def admin_unban_user():
    if not current_admin():
        abort(403)

    user_id = request.form.get("user_id")
    if not user_id:
        flash("Invalid user ID", "error")
        return redirect(url_for("admin_dashboard"))

    result = Users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"status": "active"}}
    )

    if result.modified_count > 0:
        flash("User unbanned successfully!", "success")
    else:
        flash("Failed to unban user.", "error")

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


# --- UNMUTE ROUTE ---
@app.post("/admin/unmute_user")
def admin_unmute_user():
    if not current_admin():
        abort(403)

    uid = request.form.get("user_id")
    user = Users.find_one({"_id": ObjectId(uid)})
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_dashboard"))

    Users.update_one(
        {"_id": ObjectId(uid)},
        {"$set": {"status": "active", "mute_until": None}}
    )
    flash(f"User {uid} has been unmuted.", "success")
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
    # Use platform PORT if provided (default 8080)
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)



