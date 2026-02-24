"""
Portfolio Advisory Platform — Backend v1
=========================================
Analysts maintain a watchlist of 50 stocks with ratings, IRR targets, and risk profiles.
Users take a risk questionnaire → get personalized 12-stock portfolio recommendations.
Detailed thesis & discussion requires Pro subscription.
"""

import os, time, logging, secrets, json, hmac
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import jwt as pyjwt
import requests

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
}

db = SQLAlchemy(app)

PORT = int(os.environ.get("PORT", 10000))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
RAZORPAY_MONTHLY_LINK = os.environ.get("RAZORPAY_MONTHLY_LINK", "")
RAZORPAY_QUARTERLY_LINK = os.environ.get("RAZORPAY_QUARTERLY_LINK", "")
RAZORPAY_YEARLY_LINK = os.environ.get("RAZORPAY_YEARLY_LINK", "")
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "").split(",")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("advisory")

# ═══════ CORS HANDLERS ═══════
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
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
    return response

# ═══════ DATABASE MODELS ═══════

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255))
    picture = db.Column(db.String(512))
    google_id = db.Column(db.String(128), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Subscription
    subscription_status = db.Column(db.String(50), default="free")  # free, active, expired
    subscription_plan = db.Column(db.String(50))  # monthly, quarterly, yearly
    subscription_start = db.Column(db.DateTime)
    subscription_end = db.Column(db.DateTime)
    razorpay_order_id = db.Column(db.String(128))
    razorpay_payment_id = db.Column(db.String(128))
    
    # Risk Profile
    risk_profile = db.Column(db.String(50))  # conservative, moderate, aggressive
    risk_score = db.Column(db.Integer)  # 1-100
    risk_questionnaire = db.Column(db.JSON)  # Store answers
    
    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "picture": self.picture,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "subscription_status": self.subscription_status,
            "subscription_plan": self.subscription_plan,
            "subscription_end": self.subscription_end.isoformat() if self.subscription_end else None,
            "risk_profile": self.risk_profile,
            "risk_score": self.risk_score,
            "is_admin": self.email in ADMIN_EMAILS,
        }


class Stock(db.Model):
    __tablename__ = "stocks"
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    
    # Analyst Coverage
    rating = db.Column(db.String(20))  # buy, hold, sell
    irr_target = db.Column(db.Float)  # Expected IRR %
    risk_category = db.Column(db.String(50))  # low, medium, high
    market_cap = db.Column(db.Float)  # In crores
    sector = db.Column(db.String(100))
    
    # Investment Thesis
    thesis_summary = db.Column(db.Text)  # Short summary (free)
    thesis_detailed = db.Column(db.Text)  # Full thesis (Pro only)
    holding_period = db.Column(db.String(50))  # 1-2 years, 2-3 years, 3-5 years
    entry_price = db.Column(db.Float)  # Recommended entry price
    target_price = db.Column(db.Float)
    stop_loss = db.Column(db.Float)
    
    # Metadata
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    analyst_notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self, include_detailed=False):
        data = {
            "id": self.id,
            "symbol": self.symbol,
            "name": self.name,
            "rating": self.rating,
            "irr_target": self.irr_target,
            "risk_category": self.risk_category,
            "market_cap": self.market_cap,
            "sector": self.sector,
            "thesis_summary": self.thesis_summary,
            "holding_period": self.holding_period,
            "entry_price": self.entry_price,
            "target_price": self.target_price,
            "stop_loss": self.stop_loss,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_detailed:
            data["thesis_detailed"] = self.thesis_detailed
            data["analyst_notes"] = self.analyst_notes
        return data


class PortfolioRecommendation(db.Model):
    __tablename__ = "portfolio_recommendations"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    
    # Portfolio composition (JSON array of {symbol, allocation%, reason})
    stocks = db.Column(db.JSON, nullable=False)
    risk_profile = db.Column(db.String(50))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "stocks": self.stocks,
            "risk_profile": self.risk_profile,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ═══════ AUTH HELPERS ═══════

def create_jwt(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(days=30),
        "iat": datetime.utcnow(),
    }
    return pyjwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def decode_jwt(token):
    try:
        return pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except:
        return None


def get_current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    payload = decode_jwt(token)
    if not payload:
        return None
    user = User.query.get(payload["user_id"])
    return user


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user.email not in ADMIN_EMAILS:
            return jsonify({"error": "Admin access required"}), 403
        g.user = user
        return f(*args, **kwargs)
    return wrapper


def require_pro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        if user.subscription_status != "active" or (user.subscription_end and user.subscription_end < datetime.utcnow()):
            return jsonify({"error": "Pro subscription required", "upgrade_needed": True}), 403
        g.user = user
        return f(*args, **kwargs)
    return wrapper


# ═══════ GOOGLE OAUTH ═══════

@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    data = request.json
    token = data.get("token")
    
    if not token:
        return jsonify({"error": "Token required"}), 400
    
    # Verify Google token
    try:
        r = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={token}", timeout=5)
        if r.status_code != 200:
            return jsonify({"error": "Invalid token"}), 401
        
        info = r.json()
        if info.get("aud") != GOOGLE_CLIENT_ID:
            return jsonify({"error": "Invalid token"}), 401
        
        email = info.get("email")
        name = info.get("name")
        picture = info.get("picture")
        google_id = info.get("sub")
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name, picture=picture, google_id=google_id)
            db.session.add(user)
        else:
            user.name = name
            user.picture = picture
            user.google_id = google_id
        
        db.session.commit()
        
        jwt_token = create_jwt(user.id)
        return jsonify({"token": jwt_token, "user": user.to_dict()})
    
    except Exception as e:
        log.error(f"Google auth error: {e}")
        return jsonify({"error": "Authentication failed"}), 500


@app.route("/api/auth/me")
@require_auth
def get_me():
    return jsonify({"user": g.user.to_dict()})


# ═══════ RISK QUESTIONNAIRE ═══════

@app.route("/api/questionnaire/submit", methods=["POST"])
@require_auth
def submit_questionnaire():
    """
    Submit risk questionnaire answers and calculate risk profile.
    
    Questions:
    1. Investment experience (0-4)
    2. Investment horizon (0-4)
    3. Risk tolerance (0-4)
    4. Loss reaction (0-4)
    5. Return expectations (0-4)
    6. Portfolio volatility comfort (0-4)
    7. Market decline response (0-4)
    
    Score: 0-28 → Conservative (0-10), Moderate (11-20), Aggressive (21-28)
    """
    data = request.json
    answers = data.get("answers", {})
    
    if not answers or len(answers) != 7:
        return jsonify({"error": "All 7 questions required"}), 400
    
    # Calculate risk score (0-100)
    total = sum(answers.values())
    risk_score = int((total / 28) * 100)
    
    # Determine risk profile
    if risk_score <= 35:
        risk_profile = "conservative"
    elif risk_score <= 70:
        risk_profile = "moderate"
    else:
        risk_profile = "aggressive"
    
    # Update user
    g.user.risk_score = risk_score
    g.user.risk_profile = risk_profile
    g.user.risk_questionnaire = answers
    db.session.commit()
    
    return jsonify({
        "risk_score": risk_score,
        "risk_profile": risk_profile,
        "message": "Risk profile saved successfully"
    })


# ═══════ PORTFOLIO RECOMMENDATION ENGINE ═══════

def calculate_portfolio(user):
    """
    Generate personalized 12-stock portfolio based on user's risk profile.
    
    Rules:
    - Only stocks with rating='buy' and irr_target >= 16%
    - Max 15% allocation per stock
    - Match risk category to user profile:
      * Conservative: 60% low-risk, 30% medium-risk, 10% high-risk
      * Moderate: 30% low-risk, 50% medium-risk, 20% high-risk
      * Aggressive: 15% low-risk, 35% medium-risk, 50% high-risk
    - Diversify across sectors
    - Select best IRR within each risk category
    """
    
    # Get eligible stocks (buy rating, IRR >= 16%)
    eligible_stocks = Stock.query.filter(
        Stock.rating == "buy",
        Stock.irr_target >= 16,
        Stock.is_active == True
    ).all()
    
    if not eligible_stocks:
        return None
    
    # Define allocation strategy based on risk profile
    if user.risk_profile == "conservative":
        target_allocation = {"low": 0.60, "medium": 0.30, "high": 0.10}
    elif user.risk_profile == "moderate":
        target_allocation = {"low": 0.30, "medium": 0.50, "high": 0.20}
    else:  # aggressive
        target_allocation = {"low": 0.15, "medium": 0.35, "high": 0.50}
    
    # Categorize stocks by risk
    stocks_by_risk = {"low": [], "medium": [], "high": []}
    for stock in eligible_stocks:
        if stock.risk_category in stocks_by_risk:
            stocks_by_risk[stock.risk_category].append(stock)
    
    # Sort each category by IRR (descending)
    for category in stocks_by_risk:
        stocks_by_risk[category].sort(key=lambda s: s.irr_target, reverse=True)
    
    # Calculate target number of stocks per category
    total_stocks = 12
    target_counts = {
        "low": max(1, int(total_stocks * target_allocation["low"] / 100 * 100)),
        "medium": max(1, int(total_stocks * target_allocation["medium"] / 100 * 100)),
        "high": max(1, int(total_stocks * target_allocation["high"] / 100 * 100)),
    }
    
    # Adjust to ensure we get exactly 12 stocks
    while sum(target_counts.values()) < 12:
        # Add to category with highest target allocation
        max_cat = max(target_allocation.keys(), key=lambda k: target_allocation[k])
        target_counts[max_cat] += 1
    
    while sum(target_counts.values()) > 12:
        # Remove from category with lowest target allocation
        min_cat = min(target_allocation.keys(), key=lambda k: target_allocation[k])
        if target_counts[min_cat] > 1:
            target_counts[min_cat] -= 1
    
    # Select stocks from each category
    selected_stocks = []
    sector_count = {}
    
    for risk_cat, target_count in target_counts.items():
        available = stocks_by_risk[risk_cat]
        selected_from_category = []
        
        for stock in available:
            if len(selected_from_category) >= target_count:
                break
            
            # Sector diversification - max 3 stocks per sector
            if sector_count.get(stock.sector, 0) >= 3:
                continue
            
            selected_from_category.append(stock)
            sector_count[stock.sector] = sector_count.get(stock.sector, 0) + 1
        
        selected_stocks.extend(selected_from_category)
    
    # If we don't have 12 stocks yet, fill with next best available
    if len(selected_stocks) < 12:
        remaining = [s for s in eligible_stocks if s not in selected_stocks]
        remaining.sort(key=lambda s: s.irr_target, reverse=True)
        for stock in remaining:
            if len(selected_stocks) >= 12:
                break
            if sector_count.get(stock.sector, 0) < 3:
                selected_stocks.append(stock)
                sector_count[stock.sector] = sector_count.get(stock.sector, 0) + 1
    
    # Calculate allocations (equal weight with max 15% per stock)
    num_stocks = len(selected_stocks)
    if num_stocks == 0:
        return None
    
    base_allocation = min(15.0, 100.0 / num_stocks)
    
    # Build portfolio
    portfolio = []
    total_allocation = 0
    
    for stock in selected_stocks[:12]:  # Ensure max 12
        allocation = round(base_allocation, 1)
        total_allocation += allocation
        
        portfolio.append({
            "symbol": stock.symbol,
            "name": stock.name,
            "allocation": allocation,
            "irr_target": stock.irr_target,
            "risk_category": stock.risk_category,
            "sector": stock.sector,
            "entry_price": stock.entry_price,
            "target_price": stock.target_price,
            "thesis_summary": stock.thesis_summary,
        })
    
    # Normalize allocations to 100%
    if total_allocation != 100:
        adjustment = 100.0 / total_allocation
        for item in portfolio:
            item["allocation"] = round(item["allocation"] * adjustment, 1)
    
    return portfolio


@app.route("/api/portfolio/recommend")
@require_auth
def get_portfolio_recommendation():
    """Get personalized portfolio recommendation for user."""
    
    if not g.user.risk_profile:
        return jsonify({"error": "Please complete risk questionnaire first", "questionnaire_needed": True}), 400
    
    # Generate portfolio
    portfolio = calculate_portfolio(g.user)
    
    if not portfolio:
        return jsonify({"error": "No suitable stocks available at this time"}), 404
    
    # Save recommendation
    rec = PortfolioRecommendation(
        user_id=g.user.id,
        stocks=portfolio,
        risk_profile=g.user.risk_profile
    )
    db.session.add(rec)
    db.session.commit()
    
    return jsonify({
        "portfolio": portfolio,
        "risk_profile": g.user.risk_profile,
        "total_stocks": len(portfolio),
        "recommendation_id": rec.id,
    })


@app.route("/api/portfolio/history")
@require_auth
def get_portfolio_history():
    """Get user's past portfolio recommendations."""
    recommendations = PortfolioRecommendation.query.filter_by(user_id=g.user.id).order_by(PortfolioRecommendation.created_at.desc()).limit(10).all()
    return jsonify({
        "recommendations": [rec.to_dict() for rec in recommendations]
    })


# ═══════ STOCK DETAILS (PRO ONLY) ═══════

@app.route("/api/stock/<symbol>/details")
@require_pro
def get_stock_details(symbol):
    """Get detailed thesis and analyst notes for a stock (Pro only)."""
    stock = Stock.query.filter_by(symbol=symbol.upper()).first()
    if not stock:
        return jsonify({"error": "Stock not found"}), 404
    
    return jsonify({"stock": stock.to_dict(include_detailed=True)})


# ═══════ ADMIN - STOCK MANAGEMENT ═══════

@app.route("/api/admin/stocks", methods=["GET"])
@require_admin
def admin_list_stocks():
    """List all stocks in watchlist."""
    stocks = Stock.query.order_by(Stock.updated_at.desc()).all()
    return jsonify({"stocks": [s.to_dict(include_detailed=True) for s in stocks]})


@app.route("/api/admin/stocks", methods=["POST"])
@require_admin
def admin_create_stock():
    """Add new stock to watchlist."""
    data = request.json
    
    stock = Stock(
        symbol=data["symbol"].upper(),
        name=data["name"],
        rating=data.get("rating", "hold"),
        irr_target=data.get("irr_target", 0),
        risk_category=data.get("risk_category", "medium"),
        market_cap=data.get("market_cap", 0),
        sector=data.get("sector", ""),
        thesis_summary=data.get("thesis_summary", ""),
        thesis_detailed=data.get("thesis_detailed", ""),
        holding_period=data.get("holding_period", ""),
        entry_price=data.get("entry_price", 0),
        target_price=data.get("target_price", 0),
        stop_loss=data.get("stop_loss", 0),
        analyst_notes=data.get("analyst_notes", ""),
    )
    
    db.session.add(stock)
    db.session.commit()
    
    return jsonify({"stock": stock.to_dict(include_detailed=True), "message": "Stock added successfully"})


@app.route("/api/admin/stocks/<int:stock_id>", methods=["PUT"])
@require_admin
def admin_update_stock(stock_id):
    """Update stock information."""
    stock = Stock.query.get(stock_id)
    if not stock:
        return jsonify({"error": "Stock not found"}), 404
    
    data = request.json
    
    # Update fields
    for field in ["name", "rating", "irr_target", "risk_category", "market_cap", "sector",
                  "thesis_summary", "thesis_detailed", "holding_period", "entry_price",
                  "target_price", "stop_loss", "analyst_notes", "is_active"]:
        if field in data:
            setattr(stock, field, data[field])
    
    db.session.commit()
    
    return jsonify({"stock": stock.to_dict(include_detailed=True), "message": "Stock updated successfully"})


@app.route("/api/admin/stocks/<int:stock_id>", methods=["DELETE"])
@require_admin
def admin_delete_stock(stock_id):
    """Delete stock from watchlist."""
    stock = Stock.query.get(stock_id)
    if not stock:
        return jsonify({"error": "Stock not found"}), 404
    
    db.session.delete(stock)
    db.session.commit()
    
    return jsonify({"message": "Stock deleted successfully"})


# ═══════ PAYMENT & SUBSCRIPTION ═══════

@app.route("/api/payment/links")
def get_payment_links():
    """Get Razorpay payment links."""
    return jsonify({
        "monthly": RAZORPAY_MONTHLY_LINK,
        "quarterly": RAZORPAY_QUARTERLY_LINK,
        "yearly": RAZORPAY_YEARLY_LINK,
    })


@app.route("/api/payment/webhook", methods=["POST"])
def razorpay_webhook():
    """Handle Razorpay webhook for payment confirmation."""
    
    # Verify signature
    signature = request.headers.get("X-Razorpay-Signature", "")
    body = request.get_data(as_text=True)
    
    expected_signature = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode(),
        body.encode(),
        "sha256"
    ).hexdigest()
    
    if signature != expected_signature:
        log.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 400
    
    data = request.json
    event = data.get("event")
    
    if event == "payment_link.paid":
        payload = data.get("payload", {}).get("payment_link", {}).get("entity", {})
        payment_id = payload.get("id")
        amount = payload.get("amount", 0) / 100  # Convert paise to rupees
        
        # Determine plan based on amount
        if amount >= 1999:
            plan = "yearly"
            duration_days = 365
        elif amount >= 649:
            plan = "quarterly"
            duration_days = 90
        else:
            plan = "monthly"
            duration_days = 30
        
        # Find user by email (payment link should include customer email)
        customer_email = payload.get("customer", {}).get("email")
        if customer_email:
            user = User.query.filter_by(email=customer_email).first()
            if user:
                user.subscription_status = "active"
                user.subscription_plan = plan
                user.subscription_start = datetime.utcnow()
                user.subscription_end = datetime.utcnow() + timedelta(days=duration_days)
                user.razorpay_payment_id = payment_id
                db.session.commit()
                
                log.info(f"Subscription activated for {customer_email}: {plan}")
    
    return jsonify({"status": "ok"})


# ═══════ HEALTH & INFO ═══════

@app.route("/")
def health():
    return jsonify({
        "status": "ok",
        "service": "Portfolio Advisory Platform API v1",
        "features": ["auth", "google_oauth", "risk_profiling", "portfolio_recommendations", "razorpay_subscriptions"],
    })


@app.route("/api/stats")
def get_stats():
    """Public stats."""
    total_users = User.query.count()
    total_stocks = Stock.query.filter_by(is_active=True).count()
    buy_rated_stocks = Stock.query.filter_by(rating="buy", is_active=True).count()
    
    return jsonify({
        "total_users": total_users,
        "total_stocks": total_stocks,
        "buy_rated_stocks": buy_rated_stocks,
    })


# ═══════ DB INIT & START ═══════

with app.app_context():
    db.create_all()
    log.info("Database tables created/verified")


if __name__ == "__main__":
    log.info(f"\n{'='*50}")
    log.info(f"  Portfolio Advisory Platform API")
    log.info(f"  Port: {PORT}")
    log.info(f"  Google OAuth: {'YES' if GOOGLE_CLIENT_ID else 'NO'}")
    log.info(f"  Razorpay: {'YES' if RAZORPAY_KEY_ID else 'NO'}")
    log.info(f"  Admin emails: {ADMIN_EMAILS}")
    log.info(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
