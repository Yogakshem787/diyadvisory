import os
import uuid
import json
import requests
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlencode

import psycopg2
import psycopg2.extras
import jwt
from flask import Flask, request, jsonify, redirect, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

# ─── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL    = os.environ.get("DATABASE_URL", "")
JWT_SECRET      = os.environ.get("JWT_SECRET", "dev-secret-change-me")
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_CALLBACK_URL  = os.environ.get("GOOGLE_CALLBACK_URL", "http://localhost:5000/auth/google/callback")
FRONTEND_URL    = os.environ.get("FRONTEND_URL", "http://localhost:8080")

# Fix Render postgres URL (they use postgres:// but psycopg2 needs postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ─── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        g.db.autocommit = False
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        try:
            db.close()
        except:
            pass

def query(sql, params=(), one=False, commit=False):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    if commit:
        db.commit()
    if one:
        return cur.fetchone()
    return cur.fetchall()

def execute(sql, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    db.commit()
    try:
        return cur.fetchone()
    except:
        return None

# ─── DB Init ───────────────────────────────────────────────────────────────────
def init_db():
    db = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    db.autocommit = True
    cur = db.cursor()
    cur.execute("""
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        avatar VARCHAR(500),
        google_id VARCHAR(255) UNIQUE,
        role VARCHAR(50) DEFAULT 'visitor',
        pseudonym VARCHAR(100) UNIQUE,
        bio TEXT,
        years_experience INTEGER,
        fund_type VARCHAR(100),
        is_approved BOOLEAN DEFAULT false,
        contributor_since TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ideas (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        contributor_id UUID REFERENCES users(id) ON DELETE CASCADE,
        ticker VARCHAR(20) NOT NULL,
        company_name VARCHAR(255) NOT NULL,
        sector VARCHAR(100),
        market_cap_category VARCHAR(100),
        direction VARCHAR(10) NOT NULL,
        conviction VARCHAR(20) NOT NULL,
        title VARCHAR(500) NOT NULL,
        thesis TEXT NOT NULL,
        key_risks TEXT NOT NULL,
        what_makes_me_wrong TEXT NOT NULL,
        catalysts TEXT,
        entry_price DECIMAL(12,2),
        target_price DECIMAL(12,2),
        stop_loss DECIMAL(12,2),
        target_horizon VARCHAR(50),
        position_sizing VARCHAR(100),
        is_anonymous BOOLEAN DEFAULT true,
        status VARCHAR(30) DEFAULT 'active',
        is_published BOOLEAN DEFAULT true,
        is_approved BOOLEAN DEFAULT false,
        current_return_pct DECIMAL(8,2) DEFAULT 0,
        views_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS idea_updates (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        idea_id UUID REFERENCES ideas(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        current_price DECIMAL(12,2),
        update_type VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS questions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        idea_id UUID REFERENCES ideas(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        asker_name VARCHAR(255),
        question TEXT NOT NULL,
        answer TEXT,
        answered_at TIMESTAMP,
        is_public BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS waitlist (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        role VARCHAR(50),
        message TEXT,
        linkedin VARCHAR(500),
        fund_or_firm VARCHAR(255),
        years_exp VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)
    cur.close()
    db.close()
    print("✅ Database initialized")

# ─── Auth helpers ──────────────────────────────────────────────────────────────
def make_token(user):
    payload = {
        "userId": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = query("SELECT * FROM users WHERE id = %s", (payload["userId"],), one=True)
        return user
    except:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            if user["role"] not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            g.current_user = user
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─── Google OAuth ──────────────────────────────────────────────────────────────
@app.route("/auth/google")
def google_login():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_CALLBACK_URL,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))

@app.route("/auth/google/callback")
def google_callback():
    code = request.args.get("code")
    if not code:
        return redirect(f"{FRONTEND_URL}/#auth-error")

    # Exchange code for token
    token_res = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_CALLBACK_URL,
        "grant_type": "authorization_code",
    })
    token_data = token_res.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return redirect(f"{FRONTEND_URL}/#auth-error")

    # Get user info
    user_res = requests.get("https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"})
    profile = user_res.json()

    email     = profile.get("email")
    name      = profile.get("name", email)
    avatar    = profile.get("picture", "")
    google_id = profile.get("id")

    # Find or create user
    existing = query("SELECT * FROM users WHERE google_id = %s OR email = %s", (google_id, email), one=True)
    if existing:
        execute("UPDATE users SET google_id=%s, avatar=%s, name=%s, updated_at=NOW() WHERE id=%s",
                (google_id, avatar, name, str(existing["id"])))
        user = query("SELECT * FROM users WHERE id = %s", (str(existing["id"]),), one=True)
    else:
        user = execute(
            "INSERT INTO users (email, name, avatar, google_id, role) VALUES (%s,%s,%s,%s,'visitor') RETURNING *",
            (email, name, avatar, google_id)
        )
        user = query("SELECT * FROM users WHERE email = %s", (email,), one=True)

    token = make_token(user)
    return redirect(f"{FRONTEND_URL}/#auth?token={token}")

@app.route("/auth/me")
@require_auth
def auth_me():
    u = g.current_user
    return jsonify({
        "id": str(u["id"]), "email": u["email"], "name": u["name"],
        "avatar": u["avatar"], "role": u["role"], "pseudonym": u["pseudonym"],
        "bio": u["bio"], "is_approved": u["is_approved"],
        "contributor_since": str(u["contributor_since"]) if u["contributor_since"] else None,
        "years_experience": u["years_experience"], "fund_type": u["fund_type"]
    })

@app.route("/auth/waitlist", methods=["POST"])
def join_waitlist():
    data = request.json or {}
    email = data.get("email", "").strip()
    name  = data.get("name", "").strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        execute("INSERT INTO waitlist (email, name, role) VALUES (%s,%s,'subscriber') ON CONFLICT (email) DO NOTHING", (email, name))
    except:
        pass
    return jsonify({"success": True})

@app.route("/auth/apply-contributor", methods=["POST"])
def apply_contributor():
    data = request.json or {}
    try:
        execute(
            "INSERT INTO waitlist (email, name, role, message, linkedin, fund_or_firm, years_exp) VALUES (%s,%s,'contributor',%s,%s,%s,%s) ON CONFLICT (email) DO UPDATE SET message=EXCLUDED.message",
            (data.get("email",""), data.get("name",""), data.get("message",""), data.get("linkedin",""), data.get("fund_or_firm",""), data.get("years_exp",""))
        )
    except:
        pass
    return jsonify({"success": True})

# ─── Ideas ─────────────────────────────────────────────────────────────────────
def idea_to_dict(row):
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
        elif isinstance(v, datetime):
            d[k] = v.isoformat()
    return d

@app.route("/ideas")
def list_ideas():
    filters = []
    params  = []
    filters.append("i.is_published = true AND i.is_approved = true")

    if request.args.get("direction"):
        filters.append("i.direction = %s"); params.append(request.args["direction"])
    if request.args.get("conviction"):
        filters.append("i.conviction = %s"); params.append(request.args["conviction"])
    if request.args.get("sector"):
        filters.append("i.sector = %s"); params.append(request.args["sector"])
    if request.args.get("status"):
        filters.append("i.status = %s"); params.append(request.args["status"])
    if request.args.get("search"):
        s = f"%{request.args['search']}%"
        filters.append("(i.ticker ILIKE %s OR i.company_name ILIKE %s OR i.title ILIKE %s)")
        params += [s, s, s]

    where = " AND ".join(filters)
    rows = query(f"""
        SELECT i.*,
            CASE WHEN i.is_anonymous THEN u.pseudonym ELSE u.name END as display_name,
            u.pseudonym, u.avatar,
            (SELECT COUNT(*) FROM questions q WHERE q.idea_id = i.id AND q.is_public) as question_count,
            (SELECT COUNT(*) FROM idea_updates iu WHERE iu.idea_id = i.id) as update_count
        FROM ideas i JOIN users u ON i.contributor_id = u.id
        WHERE {where}
        ORDER BY i.created_at DESC
    """, params)
    return jsonify([idea_to_dict(r) for r in rows])

@app.route("/ideas/my")
@require_auth
def my_ideas():
    rows = query("SELECT * FROM ideas WHERE contributor_id = %s ORDER BY created_at DESC", (str(g.current_user["id"]),))
    return jsonify([idea_to_dict(r) for r in rows])

@app.route("/ideas/admin/pending")
@require_role("admin")
def pending_ideas():
    rows = query("""
        SELECT i.*, u.name as contributor_name, u.pseudonym
        FROM ideas i JOIN users u ON i.contributor_id = u.id
        WHERE i.is_approved = false ORDER BY i.created_at DESC
    """)
    return jsonify([idea_to_dict(r) for r in rows])

@app.route("/ideas/<idea_id>")
def get_idea(idea_id):
    row = query("""
        SELECT i.*,
            CASE WHEN i.is_anonymous THEN u.pseudonym ELSE u.name END as display_name,
            u.pseudonym, u.avatar, u.bio, u.years_experience, u.fund_type
        FROM ideas i JOIN users u ON i.contributor_id = u.id
        WHERE i.id = %s AND i.is_published = true AND i.is_approved = true
    """, (idea_id,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    execute("UPDATE ideas SET views_count = views_count + 1 WHERE id = %s", (idea_id,))
    updates   = query("SELECT * FROM idea_updates WHERE idea_id = %s ORDER BY created_at DESC", (idea_id,))
    questions = query("SELECT * FROM questions WHERE idea_id = %s AND is_public = true ORDER BY created_at DESC", (idea_id,))
    result = idea_to_dict(row)
    result["updates"]   = [idea_to_dict(u) for u in updates]
    result["questions"] = [idea_to_dict(q) for q in questions]
    return jsonify(result)

@app.route("/ideas", methods=["POST"])
@require_role("contributor", "admin")
def submit_idea():
    d = request.json or {}
    row = execute("""
        INSERT INTO ideas (contributor_id,ticker,company_name,sector,market_cap_category,direction,conviction,
            title,thesis,key_risks,what_makes_me_wrong,catalysts,entry_price,target_price,stop_loss,
            target_horizon,position_sizing,is_anonymous,is_published,is_approved)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true,false) RETURNING *
    """, (
        str(g.current_user["id"]), d.get("ticker","").upper(), d.get("company_name",""),
        d.get("sector",""), d.get("market_cap_category",""), d.get("direction","long"),
        d.get("conviction","medium"), d.get("title",""), d.get("thesis",""),
        d.get("key_risks",""), d.get("what_makes_me_wrong",""), d.get("catalysts",""),
        d.get("entry_price") or None, d.get("target_price") or None, d.get("stop_loss") or None,
        d.get("target_horizon",""), d.get("position_sizing",""),
        d.get("is_anonymous", True)
    ))
    return jsonify(idea_to_dict(row))

@app.route("/ideas/<idea_id>/approve", methods=["POST"])
@require_role("admin")
def approve_idea(idea_id):
    execute("UPDATE ideas SET is_approved = true WHERE id = %s", (idea_id,))
    return jsonify({"success": True})

@app.route("/ideas/<idea_id>", methods=["PUT"])
@require_auth
def update_idea_status(idea_id):
    idea = query("SELECT * FROM ideas WHERE id = %s", (idea_id,), one=True)
    if not idea:
        return jsonify({"error": "Not found"}), 404
    if str(idea["contributor_id"]) != str(g.current_user["id"]) and g.current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    d = request.json or {}
    execute("UPDATE ideas SET status=COALESCE(%s,status), current_return_pct=COALESCE(%s,current_return_pct), updated_at=NOW() WHERE id=%s",
            (d.get("status"), d.get("current_return_pct"), idea_id))
    return jsonify({"success": True})

@app.route("/ideas/<idea_id>/updates", methods=["POST"])
@require_auth
def post_update(idea_id):
    idea = query("SELECT * FROM ideas WHERE id = %s", (idea_id,), one=True)
    if not idea or (str(idea["contributor_id"]) != str(g.current_user["id"]) and g.current_user["role"] != "admin"):
        return jsonify({"error": "Forbidden"}), 403
    d = request.json or {}
    row = execute("INSERT INTO idea_updates (idea_id,content,current_price,update_type) VALUES (%s,%s,%s,%s) RETURNING *",
        (idea_id, d.get("content",""), d.get("current_price") or None, d.get("update_type","thesis_update")))
    return jsonify(idea_to_dict(row))

@app.route("/ideas/<idea_id>/questions", methods=["POST"])
@require_auth
def post_question(idea_id):
    d = request.json or {}
    row = execute("INSERT INTO questions (idea_id,user_id,asker_name,question) VALUES (%s,%s,%s,%s) RETURNING *",
        (idea_id, str(g.current_user["id"]), g.current_user["name"], d.get("question","")))
    return jsonify(idea_to_dict(row))

@app.route("/ideas/<idea_id>/questions/<q_id>/answer", methods=["POST"])
@require_auth
def answer_question(idea_id, q_id):
    idea = query("SELECT * FROM ideas WHERE id = %s", (idea_id,), one=True)
    if not idea or (str(idea["contributor_id"]) != str(g.current_user["id"]) and g.current_user["role"] != "admin"):
        return jsonify({"error": "Forbidden"}), 403
    d = request.json or {}
    execute("UPDATE questions SET answer=%s, answered_at=NOW() WHERE id=%s", (d.get("answer",""), q_id))
    return jsonify({"success": True})

# ─── Users ─────────────────────────────────────────────────────────────────────
@app.route("/users/profile", methods=["PUT"])
@require_auth
def update_profile():
    d = request.json or {}
    uid = str(g.current_user["id"])
    if d.get("pseudonym"):
        taken = query("SELECT id FROM users WHERE pseudonym=%s AND id!=%s", (d["pseudonym"], uid), one=True)
        if taken:
            return jsonify({"error": "Pseudonym already taken"}), 400
    execute("""UPDATE users SET
        pseudonym=COALESCE(%s,pseudonym), bio=COALESCE(%s,bio),
        years_experience=COALESCE(%s,years_experience), fund_type=COALESCE(%s,fund_type),
        updated_at=NOW() WHERE id=%s""",
        (d.get("pseudonym"), d.get("bio"), d.get("years_experience"), d.get("fund_type"), uid))
    u = query("SELECT * FROM users WHERE id=%s", (uid,), one=True)
    return jsonify({
        "id": str(u["id"]), "pseudonym": u["pseudonym"], "bio": u["bio"],
        "years_experience": u["years_experience"], "fund_type": u["fund_type"], "role": u["role"]
    })

@app.route("/users")
@require_role("admin")
def list_users():
    rows = query("SELECT id,email,name,role,pseudonym,is_approved,created_at FROM users ORDER BY created_at DESC")
    return jsonify([idea_to_dict(r) for r in rows])

@app.route("/users/<user_id>/approve-contributor", methods=["POST"])
@require_role("admin")
def approve_contributor(user_id):
    d = request.json or {}
    execute("UPDATE users SET role='contributor', is_approved=true, contributor_since=NOW(), pseudonym=COALESCE(%s,pseudonym) WHERE id=%s",
            (d.get("pseudonym") or None, user_id))
    return jsonify({"success": True})

@app.route("/users/waitlist")
@require_role("admin")
def get_waitlist():
    rows = query("SELECT * FROM waitlist ORDER BY created_at DESC")
    return jsonify([idea_to_dict(r) for r in rows])

@app.route("/stats")
def stats():
    ideas = query("SELECT COUNT(*) as c FROM ideas WHERE is_published=true AND is_approved=true", one=True)
    contributors = query("SELECT COUNT(*) as c FROM users WHERE role='contributor' AND is_approved=true", one=True)
    return jsonify({"ideas": ideas["c"], "contributors": contributors["c"]})

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# ─── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
