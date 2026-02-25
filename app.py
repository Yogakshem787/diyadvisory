"""
Portfolio Advisory Platform — Backend v1.0
==========================================
Professional portfolio recommendations by 5+ public market analysts
- Risk profiling questionnaire
- AI-powered portfolio construction (12 stocks, max 15% per stock)
- Coverage universe: 50 stocks with IRR targets
- Weekly updates by analyst team
- Pro subscription for detailed thesis & WhatsApp access
"""

import os, time, math, logging, hashlib, secrets, json, re
import hmac as hmac_mod
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import jwt as pyjwt

# ═══════ RATE LIMITER ═══════
_rate_limits = {}

def rate_limit_check(key, max_requests, window_seconds):
    now = time.time()
    if key not in _rate_limits:
        _rate_limits[key] = []
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window_seconds]
    if len(_rate_limits[key]) >= max_requests:
        return False
    _rate_limits[key].append(now)
    return True

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

# ═══════ CONFIG ═══════
app = Flask(__name__)
ALLOWED_ORIGINS = [
    "https://diyinvesting.in",
    "https://www.diyinvesting.in",
    "https://diyrough.onrender.com",
    "http://localhost:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5500",
]
_extra = os.environ.get("EXTRA_ORIGINS", "")
if _extra:
    ALLOWED_ORIGINS += [o.strip() for o in _extra.split(",") if o.strip()]

CORS(app,
     resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Content-Type"],
     supports_credentials=True,
     max_age=3600)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///advisory.db")
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgres://", "postgresql+psycopg://", 1)
elif app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 280,
    "pool_pre_ping": True,
    "pool_size": 5,
    "max_overflow": 10,
    "connect_args": {"connect_timeout": 10},
}

db = SQLAlchemy(app)

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Vary"] = "Origin"
    # Remove COOP/COEP to allow Google OAuth popup
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
    response.headers["Cross-Origin-Embedder-Policy"] = "unsafe-none"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    response = app.make_default_options_response()
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Max-Age"] = "3600"
    return response

PORT = int(os.environ.get("PORT", 10000))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "").split(",")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
FROM_NAME = os.environ.get("FROM_NAME", "Portfolio Advisory")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://diyinvesting.in")

# Razorpay Payment Links
RAZORPAY_MONTHLY_LINK = os.environ.get("RAZORPAY_MONTHLY_LINK", "")
RAZORPAY_QUARTERLY_LINK = os.environ.get("RAZORPAY_QUARTERLY_LINK", "")
RAZORPAY_YEARLY_LINK = os.environ.get("RAZORPAY_YEARLY_LINK", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("advisory")

# ═══════ EMAIL HELPERS ═══════
def send_email(to_email, subject, html_body):
    if not SMTP_USER or not SMTP_PASS:
        log.warning("[EMAIL] SMTP not configured")
        return False
    
    import threading
    def _send():
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{FROM_NAME} <{SMTP_USER}>"
            msg["To"] = to_email
            msg.attach(MIMEText(html_body, "html"))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, to_email, msg.as_string())
            log.info(f"[EMAIL] Sent to {to_email}: {subject}")
        except Exception as e:
            log.error(f"[EMAIL ERROR] {to_email}: {e}")
    
    t = threading.Thread(target=_send, daemon=True)
    t.start()
    return True

def welcome_email(user):
    send_email(
        user.email,
        "Welcome to Portfolio Advisory! 🎯",
        f"""
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
            <div style="background:linear-gradient(135deg,#0c1220,#1e293b);border-radius:12px;padding:28px;text-align:center;margin-bottom:20px">
                <h1 style="color:#f1f5f9;font-size:22px;margin:0 0 4px">Welcome, {user.name or 'Investor'}!</h1>
                <p style="color:#94a3b8;font-size:13px;margin:0">Expert portfolio recommendations await</p>
            </div>
            <h2 style="font-size:16px;color:#0f172a;margin-bottom:12px">What's next?</h2>
            <ul style="color:#334155;font-size:13px;line-height:2">
                <li>📋 Complete your risk profile assessment</li>
                <li>🎯 Get personalized 12-stock portfolio</li>
                <li>📊 Coverage universe: 50 analyst-curated stocks</li>
                <li>💬 Pro: Unlock thesis & analyst access</li>
            </ul>
            <div style="text-align:center;margin:24px 0">
                <a href="{FRONTEND_URL}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff;font-weight:700;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px">Get Your Portfolio →</a>
            </div>
            <p style="color:#94a3b8;font-size:11px;text-align:center;margin-top:24px;border-top:1px solid #e5e7eb;padding-top:16px">
                Portfolio Advisory · Research by 5+ public market analysts<br/>
                Not financial advice · Always DYOR
            </p>
        </div>
        """
    )

# ═══════ DATABASE MODELS ═══════
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), default="")
    phone = db.Column(db.String(20), default="")
    password_hash = db.Column(db.String(255), default="")
    google_id = db.Column(db.String(255), default="")
    avatar_url = db.Column(db.String(500), default="")
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Subscription
    plan = db.Column(db.String(20), default="free")
    plan_expires = db.Column(db.DateTime, nullable=True)
    razorpay_payment_id = db.Column(db.String(255), default="")
    total_paid = db.Column(db.Float, default=0)
    
    # Risk Profile
    risk_profile_completed = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer, default=0)  # 0-100
    risk_category = db.Column(db.String(20), default="")  # conservative, moderate, aggressive
    profile_data = db.Column(db.Text, default="{}")  # JSON: questionnaire responses
    
    # Engagement
    login_count = db.Column(db.Integer, default=0)
    portfolio_views = db.Column(db.Integer, default=0)
    
    def is_pro(self):
        if self.is_admin:
            return True
        if self.plan == "free":
            return False
        return self.plan_expires and datetime.utcnow() < self.plan_expires
    
    def days_left(self):
        if not self.plan_expires:
            return 0
        d = (self.plan_expires - datetime.utcnow()).days
        return max(0, d)
    
    def to_dict(self, include_private=False):
        d = {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "phone": self.phone,
            "avatar": self.avatar_url,
            "isAdmin": self.is_admin,
            "plan": self.plan,
            "isPro": self.is_pro(),
            "daysLeft": self.days_left(),
            "planExpires": self.plan_expires.isoformat() if self.plan_expires else None,
            "createdAt": self.created_at.isoformat(),
            "hasGoogle": bool(self.google_id),
            "hasPassword": bool(self.password_hash),
            "riskProfileCompleted": self.risk_profile_completed,
            "riskCategory": self.risk_category,
        }
        if include_private:
            d["loginCount"] = self.login_count
            d["portfolioViews"] = self.portfolio_views
            d["totalPaid"] = self.total_paid
            d["riskScore"] = self.risk_score
        return d


class CoverageStock(db.Model):
    """
    Analyst coverage universe - 50 stocks maintained by the team
    Updated weekly via admin panel
    """
    __tablename__ = "coverage_stocks"
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(30), nullable=False, unique=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    sector = db.Column(db.String(100), default="")
    
    # Analyst ratings & targets
    rating = db.Column(db.String(20), default="BUY")  # BUY, HOLD, SELL
    irr_target = db.Column(db.Float, default=0)  # Expected IRR % per annum
    target_price = db.Column(db.Float, default=0)
    current_price = db.Column(db.Float, default=0)
    
    # Risk classification
    risk_profile = db.Column(db.String(20), default="moderate")  # conservative, moderate, aggressive
    volatility_score = db.Column(db.Integer, default=50)  # 0-100
    
    # Fundamentals
    market_cap_cr = db.Column(db.Float, default=0)  # Crores
    pe_ratio = db.Column(db.Float, default=0)
    debt_to_equity = db.Column(db.Float, default=0)
    roe = db.Column(db.Float, default=0)
    
    # Investment thesis (Pro users only)
    thesis = db.Column(db.Text, default="")
    catalysts = db.Column(db.Text, default="")
    risks = db.Column(db.Text, default="")
    holding_period = db.Column(db.String(50), default="6-12 months")
    
    # Metadata
    analyst_confidence = db.Column(db.Integer, default=75)  # 0-100
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self, include_thesis=False):
        d = {
            "id": self.id,
            "symbol": self.symbol,
            "name": self.name,
            "sector": self.sector,
            "rating": self.rating,
            "irrTarget": self.irr_target,
            "targetPrice": self.target_price,
            "currentPrice": self.current_price,
            "riskProfile": self.risk_profile,
            "volatilityScore": self.volatility_score,
            "marketCapCr": self.market_cap_cr,
            "peRatio": self.pe_ratio,
            "debtToEquity": self.debt_to_equity,
            "roe": self.roe,
            "analystConfidence": self.analyst_confidence,
            "lastUpdated": self.last_updated.isoformat(),
        }
        if include_thesis:
            d.update({
                "thesis": self.thesis,
                "catalysts": self.catalysts,
                "risks": self.risks,
                "holdingPeriod": self.holding_period,
            })
        return d


class RecommendedPortfolio(db.Model):
    """
    User's recommended portfolio - generated based on risk profile
    """
    __tablename__ = "recommended_portfolios"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    
    # Portfolio composition (JSON array of {symbol, allocation%})
    stocks = db.Column(db.Text, default="[]")  # [{symbol, allocation, ...}, ...]
    
    # Performance metrics
    total_irr_target = db.Column(db.Float, default=0)
    risk_score = db.Column(db.Integer, default=0)
    diversification_score = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    valid_until = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=7))
    
    def to_dict(self):
        return {
            "id": self.id,
            "stocks": json.loads(self.stocks) if self.stocks else [],
            "totalIRRTarget": self.total_irr_target,
            "riskScore": self.risk_score,
            "diversificationScore": self.diversification_score,
            "createdAt": self.created_at.isoformat(),
            "validUntil": self.valid_until.isoformat(),
        }


class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    razorpay_payment_id = db.Column(db.String(255), default="")
    razorpay_order_id = db.Column(db.String(255), default="")
    amount = db.Column(db.Float, default=0)
    plan = db.Column(db.String(20), default="")
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ═══════ AUTH HELPERS ═══════
def hash_password(pwd):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 200000)
    return salt + ":" + h.hex()

def verify_password(pwd, stored):
    if not stored or ":" not in stored:
        return False
    salt, h = stored.split(":", 1)
    h2 = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 200000)
    return h == h2.hex()

def make_token(user):
    payload = {
        "uid": user.id,
        "email": user.email,
        "admin": user.is_admin,
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    return pyjwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            return jsonify({"error": "Login required"}), 401
        try:
            data = pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.user = User.query.get(data["uid"])
            if not g.user:
                return jsonify({"error": "User not found"}), 401
            return f(*args, **kwargs)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            log.error(f"[AUTH ERROR] {e}")
            return jsonify({"error": "Invalid token"}), 401
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            return jsonify({"error": "Login required"}), 401
        try:
            data = pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.user = User.query.get(data["uid"])
            if not g.user:
                return jsonify({"error": "User not found"}), 401
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401
        if not g.user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ═══════ PORTFOLIO RECOMMENDATION ENGINE ═══════
def calculate_risk_score(responses):
    """
    Calculate risk score (0-100) from questionnaire responses
    Higher score = higher risk tolerance
    """
    score = 0
    
    # Q1: Investment horizon (0-25 points)
    horizon = responses.get("horizon", "medium")
    horizon_map = {"short": 5, "medium": 15, "long": 25}
    score += horizon_map.get(horizon, 15)
    
    # Q2: Age (0-20 points)
    age = responses.get("age", 35)
    if age < 30:
        score += 20
    elif age < 40:
        score += 15
    elif age < 50:
        score += 10
    else:
        score += 5
    
    # Q3: Income stability (0-15 points)
    income = responses.get("income_stability", "moderate")
    income_map = {"low": 5, "moderate": 10, "high": 15}
    score += income_map.get(income, 10)
    
    # Q4: Loss tolerance (0-25 points)
    loss = responses.get("loss_tolerance", "moderate")
    loss_map = {"low": 5, "moderate": 15, "high": 25}
    score += loss_map.get(loss, 15)
    
    # Q5: Investment experience (0-15 points)
    experience = responses.get("experience", "intermediate")
    exp_map = {"beginner": 5, "intermediate": 10, "advanced": 15}
    score += exp_map.get(experience, 10)
    
    return min(100, max(0, score))

def get_risk_category(score):
    """Convert risk score to category"""
    if score < 35:
        return "conservative"
    elif score < 65:
        return "moderate"
    else:
        return "aggressive"

def build_portfolio(user_risk_category, user_risk_score):
    """
    Build optimal 12-stock portfolio based on user risk profile
    
    Rules:
    - Only BUY rated stocks with IRR >= 16%
    - Max 15% allocation per stock
    - Match stocks to user risk profile
    - Optimize for highest IRR while maintaining diversification
    """
    # Fetch eligible stocks
    eligible_stocks = CoverageStock.query.filter(
        CoverageStock.is_active == True,
        CoverageStock.rating == "BUY",
        CoverageStock.irr_target >= 16.0
    ).all()
    
    if len(eligible_stocks) == 0:
        return None
    
    # Score each stock for this user
    scored_stocks = []
    for stock in eligible_stocks:
        # Risk match score (0-100)
        risk_match = 100 - abs(user_risk_score - stock.volatility_score)
        
        # IRR attractiveness (normalize to 0-100)
        irr_score = min(100, (stock.irr_target / 30) * 100)
        
        # Analyst confidence
        confidence_score = stock.analyst_confidence
        
        # Combined score
        total_score = (risk_match * 0.4) + (irr_score * 0.4) + (confidence_score * 0.2)
        
        scored_stocks.append({
            "stock": stock,
            "score": total_score,
            "risk_match": risk_match,
            "irr_score": irr_score,
        })
    
    # Sort by score descending
    scored_stocks.sort(key=lambda x: x["score"], reverse=True)
    
    # Select top 12 (or less if not enough stocks)
    selected = scored_stocks[:12]
    
    # Calculate allocations
    # Base allocation: equal weight with adjustments for score
    total_score = sum(s["score"] for s in selected)
    
    portfolio_stocks = []
    for item in selected:
        stock = item["stock"]
        
        # Score-weighted allocation
        base_allocation = (item["score"] / total_score) * 100
        
        # Cap at 15%
        allocation = min(15.0, base_allocation)
        
        portfolio_stocks.append({
            "symbol": stock.symbol,
            "name": stock.name,
            "sector": stock.sector,
            "allocation": round(allocation, 2),
            "irrTarget": stock.irr_target,
            "targetPrice": stock.target_price,
            "currentPrice": stock.current_price,
            "riskProfile": stock.risk_profile,
            "rating": stock.rating,
        })
    
    # Normalize allocations to sum to 100%
    total_allocation = sum(s["allocation"] for s in portfolio_stocks)
    if total_allocation > 0:
        for stock in portfolio_stocks:
            stock["allocation"] = round((stock["allocation"] / total_allocation) * 100, 2)
    
    # Calculate portfolio metrics
    avg_irr = sum(s["irrTarget"] * s["allocation"] for s in portfolio_stocks) / 100
    
    # Sector diversification score
    sectors = {}
    for s in portfolio_stocks:
        sectors[s["sector"]] = sectors.get(s["sector"], 0) + s["allocation"]
    max_sector_concentration = max(sectors.values()) if sectors else 0
    diversification_score = int(100 - max_sector_concentration)
    
    return {
        "stocks": portfolio_stocks,
        "total_irr_target": round(avg_irr, 2),
        "risk_score": user_risk_score,
        "diversification_score": diversification_score,
    }


# ═══════ AUTH ROUTES ═══════
@app.route("/api/auth/signup", methods=["POST"])
def signup():
    ip = get_client_ip()
    if not rate_limit_check(f"signup:{ip}", 5, 600):
        return jsonify({"error": "Too many signup attempts"}), 429
    
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()
    
    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not name:
        return jsonify({"error": "Name is required"}), 400
    
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": "Email already registered"}), 400
    
    u = User(
        email=email,
        name=name,
        phone=phone,
        password_hash=hash_password(password),
        is_admin=(email in ADMIN_EMAILS),
    )
    db.session.add(u)
    db.session.commit()
    log.info(f"[SIGNUP] {email}")
    
    try:
        welcome_email(u)
    except Exception as e:
        log.warning(f"[SIGNUP EMAIL] {e}")
    
    return jsonify({"token": make_token(u), "user": u.to_dict()})


@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = get_client_ip()
    if not rate_limit_check(f"login:{ip}", 10, 300):
        return jsonify({"error": "Too many login attempts"}), 429
    
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    u = User.query.filter_by(email=email).first()
    if not u or not verify_password(password, u.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401
    
    u.login_count = (u.login_count or 0) + 1
    u.last_login = datetime.utcnow()
    db.session.commit()
    log.info(f"[LOGIN] {email}")
    
    return jsonify({"token": make_token(u), "user": u.to_dict()})


@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    ip = get_client_ip()
    if not rate_limit_check(f"gauth:{ip}", 10, 300):
        return jsonify({"error": "Too many attempts"}), 429
    
    # Set CORS headers explicitly for Google OAuth
    origin = request.headers.get("Origin", "")
    
    data = request.json or {}
    credential = data.get("credential")
    if not credential:
        return jsonify({"error": "No credential"}), 400
    
    try:
        info = None
        last_error = None
        
        # Try to validate token with Google
        for attempt in range(3):
            try:
                r = requests.get(
                    f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}",
                    timeout=15,
                    headers={
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': 'application/json'
                    }
                )
                if r.status_code == 200:
                    info = r.json()
                    break
                last_error = f"Google API returned status {r.status_code}"
                log.error(f"[GOOGLE] Attempt {attempt+1}: {last_error}")
            except requests.exceptions.Timeout:
                last_error = "Request timeout"
                log.error(f"[GOOGLE] Attempt {attempt+1}: Timeout")
            except Exception as e:
                last_error = str(e)
                log.error(f"[GOOGLE] Attempt {attempt+1}: {e}")
            
            if attempt < 2:
                time.sleep(0.5)
        
        if not info:
            log.error(f"[GOOGLE] Token validation failed after 3 attempts: {last_error}")
            return jsonify({"error": "Could not verify with Google. Please try again or use email login."}), 400
        
        aud = info.get("aud", "")
        if GOOGLE_CLIENT_ID and aud and aud != GOOGLE_CLIENT_ID:
            return jsonify({"error": "Invalid token audience"}), 400
        
        email = info.get("email", "").lower()
        name = info.get("name", "") or info.get("given_name", "")
        picture = info.get("picture", "")
        google_id = info.get("sub", "")
        
        if not email:
            return jsonify({"error": "No email from Google"}), 400
        if info.get("email_verified") == "false":
            return jsonify({"error": "Google email not verified"}), 400
        
        u = User.query.filter_by(email=email).first()
        is_new = False
        if not u:
            is_new = True
            u = User(
                email=email,
                name=name,
                google_id=google_id,
                avatar_url=picture,
                is_admin=(email in ADMIN_EMAILS),
            )
            db.session.add(u)
        else:
            u.google_id = google_id
            u.avatar_url = picture
            if not u.name and name:
                u.name = name
        
        u.login_count = (u.login_count or 0) + 1
        u.last_login = datetime.utcnow()
        db.session.commit()
        
        if is_new:
            try:
                welcome_email(u)
            except Exception as e:
                log.warning(f"[GOOGLE WELCOME EMAIL] {e}")
        
        log.info(f"[GOOGLE LOGIN] {email} (new={is_new})")
        return jsonify({"token": make_token(u), "user": u.to_dict()})
    
    except Exception as e:
        log.error(f"[GOOGLE ERROR] {str(e)}", exc_info=True)
        return jsonify({"error": "Google login failed"}), 500


@app.route("/api/auth/me")
@auth_required
def auth_me():
    return jsonify({"user": g.user.to_dict()})


# ═══════ RISK PROFILING ROUTES ═══════
@app.route("/api/risk-profile/questions")
def get_questionnaire():
    """Return the risk profiling questionnaire"""
    questions = [
        {
            "id": "horizon",
            "question": "What is your investment time horizon?",
            "type": "single",
            "options": [
                {"value": "short", "label": "Short-term (< 1 year)", "desc": "I want quick returns"},
                {"value": "medium", "label": "Medium-term (1-3 years)", "desc": "Balanced approach"},
                {"value": "long", "label": "Long-term (3+ years)", "desc": "I can wait for growth"},
            ]
        },
        {
            "id": "age",
            "question": "What is your age?",
            "type": "number",
            "placeholder": "Enter your age",
            "min": 18,
            "max": 100,
        },
        {
            "id": "income_stability",
            "question": "How stable is your income?",
            "type": "single",
            "options": [
                {"value": "low", "label": "Irregular income", "desc": "Freelance or variable pay"},
                {"value": "moderate", "label": "Moderately stable", "desc": "Some variability"},
                {"value": "high", "label": "Very stable", "desc": "Salaried with secure job"},
            ]
        },
        {
            "id": "loss_tolerance",
            "question": "How would you react to a 20% portfolio loss?",
            "type": "single",
            "options": [
                {"value": "low", "label": "Very concerned", "desc": "I'd want to exit immediately"},
                {"value": "moderate", "label": "Somewhat worried", "desc": "I'd hold but feel anxious"},
                {"value": "high", "label": "Stay calm", "desc": "It's a buying opportunity"},
            ]
        },
        {
            "id": "experience",
            "question": "What's your stock market experience?",
            "type": "single",
            "options": [
                {"value": "beginner", "label": "New investor", "desc": "< 1 year"},
                {"value": "intermediate", "label": "Some experience", "desc": "1-5 years"},
                {"value": "advanced", "label": "Experienced", "desc": "5+ years"},
            ]
        },
        {
            "id": "goals",
            "question": "What's your primary investment goal?",
            "type": "single",
            "options": [
                {"value": "wealth", "label": "Wealth creation", "desc": "Long-term growth"},
                {"value": "income", "label": "Regular income", "desc": "Dividends & stability"},
                {"value": "balanced", "label": "Balanced", "desc": "Growth + some income"},
            ]
        },
    ]
    
    return jsonify({"questions": questions})


@app.route("/api/risk-profile/submit", methods=["POST"])
@auth_required
def submit_risk_profile():
    """Process risk profile questionnaire and generate portfolio"""
    data = request.json or {}
    responses = data.get("responses", {})
    
    if not responses:
        return jsonify({"error": "No responses provided"}), 400
    
    # Calculate risk score
    risk_score = calculate_risk_score(responses)
    risk_category = get_risk_category(risk_score)
    
    # Update user profile
    g.user.risk_profile_completed = True
    g.user.risk_score = risk_score
    g.user.risk_category = risk_category
    g.user.profile_data = json.dumps(responses)
    
    # Generate portfolio
    portfolio_data = build_portfolio(risk_category, risk_score)
    
    if not portfolio_data:
        db.session.commit()
        return jsonify({"error": "No suitable stocks available. Please try again later."}), 404
    
    # Save recommended portfolio
    existing_portfolio = RecommendedPortfolio.query.filter_by(user_id=g.user.id).first()
    if existing_portfolio:
        # Update existing
        existing_portfolio.stocks = json.dumps(portfolio_data["stocks"])
        existing_portfolio.total_irr_target = portfolio_data["total_irr_target"]
        existing_portfolio.risk_score = portfolio_data["risk_score"]
        existing_portfolio.diversification_score = portfolio_data["diversification_score"]
        existing_portfolio.created_at = datetime.utcnow()
        existing_portfolio.valid_until = datetime.utcnow() + timedelta(days=7)
    else:
        # Create new
        portfolio = RecommendedPortfolio(
            user_id=g.user.id,
            stocks=json.dumps(portfolio_data["stocks"]),
            total_irr_target=portfolio_data["total_irr_target"],
            risk_score=portfolio_data["risk_score"],
            diversification_score=portfolio_data["diversification_score"],
        )
        db.session.add(portfolio)
    
    db.session.commit()
    
    log.info(f"[RISK PROFILE] {g.user.email}: {risk_category} ({risk_score})")
    
    return jsonify({
        "riskScore": risk_score,
        "riskCategory": risk_category,
        "portfolio": portfolio_data,
    })


@app.route("/api/portfolio/recommended")
@auth_required
def get_recommended_portfolio():
    """Get user's recommended portfolio"""
    if not g.user.risk_profile_completed:
        return jsonify({"error": "Complete risk profile first"}), 400
    
    portfolio = RecommendedPortfolio.query.filter_by(user_id=g.user.id).first()
    if not portfolio:
        return jsonify({"error": "No portfolio generated"}), 404
    
    g.user.portfolio_views = (g.user.portfolio_views or 0) + 1
    db.session.commit()
    
    return jsonify(portfolio.to_dict())


@app.route("/api/portfolio/refresh", methods=["POST"])
@auth_required
def refresh_portfolio():
    """Regenerate portfolio with current coverage data"""
    if not g.user.risk_profile_completed:
        return jsonify({"error": "Complete risk profile first"}), 400
    
    # Generate new portfolio
    portfolio_data = build_portfolio(g.user.risk_category, g.user.risk_score)
    
    if not portfolio_data:
        return jsonify({"error": "No suitable stocks available"}), 404
    
    # Update existing portfolio
    portfolio = RecommendedPortfolio.query.filter_by(user_id=g.user.id).first()
    if portfolio:
        portfolio.stocks = json.dumps(portfolio_data["stocks"])
        portfolio.total_irr_target = portfolio_data["total_irr_target"]
        portfolio.risk_score = portfolio_data["risk_score"]
        portfolio.diversification_score = portfolio_data["diversification_score"]
        portfolio.created_at = datetime.utcnow()
        portfolio.valid_until = datetime.utcnow() + timedelta(days=7)
    else:
        portfolio = RecommendedPortfolio(
            user_id=g.user.id,
            stocks=json.dumps(portfolio_data["stocks"]),
            total_irr_target=portfolio_data["total_irr_target"],
            risk_score=portfolio_data["risk_score"],
            diversification_score=portfolio_data["diversification_score"],
        )
        db.session.add(portfolio)
    
    db.session.commit()
    
    return jsonify(portfolio.to_dict())


@app.route("/api/stock/<symbol>/thesis")
@auth_required
def get_stock_thesis(symbol):
    """Get detailed stock thesis (Pro users only)"""
    stock = CoverageStock.query.filter_by(symbol=symbol.upper()).first()
    if not stock:
        return jsonify({"error": "Stock not found"}), 404
    
    # Check if user is Pro
    if not g.user.is_pro():
        return jsonify({
            "error": "Pro subscription required",
            "needsUpgrade": True,
            "preview": {
                "symbol": stock.symbol,
                "name": stock.name,
                "irrTarget": stock.irr_target,
                "rating": stock.rating,
            }
        }), 403
    
    return jsonify(stock.to_dict(include_thesis=True))


# ═══════ PAYMENT ROUTES ═══════
@app.route("/api/payment/links")
def get_payment_links():
    return jsonify({
        "monthly": RAZORPAY_MONTHLY_LINK,
        "quarterly": RAZORPAY_QUARTERLY_LINK,
        "yearly": RAZORPAY_YEARLY_LINK,
        "return_url": FRONTEND_URL,
    })


@app.route("/api/payment/webhook", methods=["POST"])
def payment_webhook():
    """Razorpay webhook for payment confirmations"""
    try:
        if RAZORPAY_WEBHOOK_SECRET:
            sig = request.headers.get("X-Razorpay-Signature", "")
            body = request.get_data()
            expected = hmac_mod.new(
                RAZORPAY_WEBHOOK_SECRET.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            if not sig or sig != expected:
                log.error("[WEBHOOK] Invalid signature")
                return jsonify({"error": "Invalid signature"}), 400
        
        data = request.json or {}
        event = data.get("event", "")
        log.info(f"[WEBHOOK] Event: {event}")
        
        if event == "payment_link.paid":
            payload = data.get("payload", {})
            payment_link = payload.get("payment_link", {}).get("entity",
                           payload.get("payment_link", {}))
            payment = payload.get("payment", {}).get("entity",
                      payload.get("payment", {}))
            
            notes = payment_link.get("notes", {}) or {}
            customer = payment_link.get("customer", {}) or {}
            payment_notes = payment.get("notes", {}) or {}
            
            email = (notes.get("email") or 
                     customer.get("email") or
                     payment.get("email") or 
                     payment_notes.get("email") or
                     "").strip().lower()
            plan = (notes.get("plan") or 
                    payment_notes.get("plan") or
                    "monthly")
            amount = payment.get("amount", 0) / 100
            pay_id = payment.get("id", "")
            
            log.info(f"[WEBHOOK] Payment: {email}, {plan}, ₹{amount}, {pay_id}")
            
            if not email:
                log.error("[WEBHOOK] No email")
                return jsonify({"status": "ok", "warning": "no_email"})
            
            user = User.query.filter_by(email=email).first()
            if not user:
                log.error(f"[WEBHOOK] User not found: {email}")
                return jsonify({"status": "ok", "warning": "user_not_found"})
            
            days_map = {"monthly": 30, "quarterly": 90, "yearly": 365}
            days = days_map.get(plan, 30)
            
            if user.is_pro() and user.plan_expires and user.plan_expires > datetime.utcnow():
                user.plan_expires = user.plan_expires + timedelta(days=days)
            else:
                user.plan_expires = datetime.utcnow() + timedelta(days=days)
            
            user.plan = plan
            user.razorpay_payment_id = pay_id
            user.total_paid = (user.total_paid or 0) + amount
            
            existing_payment = Payment.query.filter_by(razorpay_payment_id=pay_id).first()
            if not existing_payment:
                p = Payment(
                    user_id=user.id,
                    razorpay_payment_id=pay_id,
                    amount=amount,
                    plan=plan,
                    status="success",
                )
                db.session.add(p)
            
            db.session.commit()
            log.info(f"[WEBHOOK] ✅ Upgraded {email} to {plan}")
        
        return jsonify({"status": "ok"})
    
    except Exception as e:
        log.error(f"[WEBHOOK ERROR] {e}", exc_info=True)
        return jsonify({"status": "ok", "error": str(e)})


@app.route("/api/payment/verify", methods=["POST"])
@auth_required
def verify_payment():
    fresh_user = User.query.get(g.user.id)
    return jsonify({
        "user": fresh_user.to_dict(),
        "isPro": fresh_user.is_pro(),
        "plan": fresh_user.plan,
        "planExpires": fresh_user.plan_expires.isoformat() if fresh_user.plan_expires else None,
    })


# ═══════ ADMIN ROUTES ═══════
@app.route("/api/admin/coverage")
@admin_required
def admin_get_coverage():
    """Get all coverage stocks"""
    stocks = CoverageStock.query.order_by(CoverageStock.symbol).all()
    return jsonify([s.to_dict(include_thesis=True) for s in stocks])


@app.route("/api/admin/coverage", methods=["POST"])
@admin_required
def admin_create_stock():
    """Add stock to coverage universe"""
    data = request.json or {}
    
    symbol = data.get("symbol", "").upper().strip()
    if not symbol:
        return jsonify({"error": "Symbol required"}), 400
    
    existing = CoverageStock.query.filter_by(symbol=symbol).first()
    if existing:
        return jsonify({"error": "Stock already in coverage"}), 400
    
    stock = CoverageStock(
        symbol=symbol,
        name=data.get("name", ""),
        sector=data.get("sector", ""),
        rating=data.get("rating", "BUY"),
        irr_target=float(data.get("irrTarget", 0)),
        target_price=float(data.get("targetPrice", 0)),
        current_price=float(data.get("currentPrice", 0)),
        risk_profile=data.get("riskProfile", "moderate"),
        volatility_score=int(data.get("volatilityScore", 50)),
        market_cap_cr=float(data.get("marketCapCr", 0)),
        pe_ratio=float(data.get("peRatio", 0)),
        debt_to_equity=float(data.get("debtToEquity", 0)),
        roe=float(data.get("roe", 0)),
        thesis=data.get("thesis", ""),
        catalysts=data.get("catalysts", ""),
        risks=data.get("risks", ""),
        holding_period=data.get("holdingPeriod", "6-12 months"),
        analyst_confidence=int(data.get("analystConfidence", 75)),
    )
    
    db.session.add(stock)
    db.session.commit()
    
    log.info(f"[ADMIN] Added {symbol} to coverage")
    return jsonify(stock.to_dict(include_thesis=True))


@app.route("/api/admin/coverage/<int:stock_id>", methods=["PUT"])
@admin_required
def admin_update_stock(stock_id):
    """Update coverage stock"""
    stock = CoverageStock.query.get(stock_id)
    if not stock:
        return jsonify({"error": "Stock not found"}), 404
    
    data = request.json or {}
    
    # Update fields
    if "name" in data:
        stock.name = data["name"]
    if "sector" in data:
        stock.sector = data["sector"]
    if "rating" in data:
        stock.rating = data["rating"]
    if "irrTarget" in data:
        stock.irr_target = float(data["irrTarget"])
    if "targetPrice" in data:
        stock.target_price = float(data["targetPrice"])
    if "currentPrice" in data:
        stock.current_price = float(data["currentPrice"])
    if "riskProfile" in data:
        stock.risk_profile = data["riskProfile"]
    if "volatilityScore" in data:
        stock.volatility_score = int(data["volatilityScore"])
    if "marketCapCr" in data:
        stock.market_cap_cr = float(data["marketCapCr"])
    if "peRatio" in data:
        stock.pe_ratio = float(data["peRatio"])
    if "debtToEquity" in data:
        stock.debt_to_equity = float(data["debtToEquity"])
    if "roe" in data:
        stock.roe = float(data["roe"])
    if "thesis" in data:
        stock.thesis = data["thesis"]
    if "catalysts" in data:
        stock.catalysts = data["catalysts"]
    if "risks" in data:
        stock.risks = data["risks"]
    if "holdingPeriod" in data:
        stock.holding_period = data["holdingPeriod"]
    if "analystConfidence" in data:
        stock.analyst_confidence = int(data["analystConfidence"])
    if "isActive" in data:
        stock.is_active = data["isActive"]
    
    stock.last_updated = datetime.utcnow()
    db.session.commit()
    
    log.info(f"[ADMIN] Updated {stock.symbol}")
    return jsonify(stock.to_dict(include_thesis=True))


@app.route("/api/admin/coverage/<int:stock_id>", methods=["DELETE"])
@admin_required
def admin_delete_stock(stock_id):
    """Remove stock from coverage"""
    stock = CoverageStock.query.get(stock_id)
    if not stock:
        return jsonify({"error": "Stock not found"}), 404
    
    symbol = stock.symbol
    db.session.delete(stock)
    db.session.commit()
    
    log.info(f"[ADMIN] Deleted {symbol}")
    return jsonify({"status": "deleted"})


@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    """Admin dashboard stats"""
    total_users = User.query.count()
    profiles_completed = User.query.filter_by(risk_profile_completed=True).count()
    pro_users = User.query.filter(User.plan.in_(["monthly", "quarterly", "yearly"])).count()
    revenue = db.session.query(db.func.sum(User.total_paid)).scalar() or 0
    
    coverage_count = CoverageStock.query.filter_by(is_active=True).count()
    buy_rated = CoverageStock.query.filter_by(is_active=True, rating="BUY").count()
    
    return jsonify({
        "totalUsers": total_users,
        "profilesCompleted": profiles_completed,
        "proUsers": pro_users,
        "revenue": round(revenue, 2),
        "coverageStocks": coverage_count,
        "buyRated": buy_rated,
    })


# ═══════ HEALTH CHECK ═══════
@app.route("/")
def health():
    return jsonify({
        "status": "ok",
        "service": "Portfolio Advisory Platform v1.0",
        "features": ["risk_profiling", "portfolio_recommendation", "analyst_coverage"],
    })


# ═══════ DB INIT & START ═══════
with app.app_context():
    db.create_all()
    log.info("Database tables created/verified")

if __name__ == "__main__":
    log.info(f"\n{'='*50}")
    log.info(f"  Portfolio Advisory Platform")
    log.info(f"  Port: {PORT}")
    log.info(f"  DB: {app.config['SQLALCHEMY_DATABASE_URI'][:40]}...")
    log.info(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
