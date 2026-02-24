# Portfolio Advisory Platform — Implementation Guide

## 🎯 What Changed

Your website has been completely revamped from a DIY investing platform to a **Portfolio Advisory Model**:

### Old System (Removed)
- ❌ Reverse DCF calculator
- ❌ Stock screener
- ❌ User watchlists
- ❌ Complex stock analysis tools

### New System (Implemented)
- ✅ **Analyst Watchlist**: Team of 5 analysts maintain 50-stock coverage
- ✅ **Risk Profiling**: 7-question questionnaire to assess user risk appetite
- ✅ **Smart Portfolio Engine**: Generates personalized 12-stock portfolios
- ✅ **Pro Subscription**: Detailed thesis & analyst discussions behind paywall
- ✅ **Admin Dashboard**: Easy stock management interface for analysts

---

## 📁 New File Structure

```
portfolio-advisory/
├── app.py                 # Backend API
├── index.html            # Main user-facing website
├── admin.html            # Admin dashboard for analysts
├── requirements.txt      # Python dependencies
├── Procfile             # Render deployment config
├── runtime.txt          # Python version
└── render.yaml          # Render service config
```

---

## 🚀 Quick Start (5 Steps)

### Step 1: Update Dependencies

The new `requirements.txt` is simpler (removed unused packages):

```txt
flask==3.1.0
flask-cors==5.0.1
flask-sqlalchemy==3.1.1
psycopg2-binary
psycopg[binary]
sqlalchemy[postgresql_psycopg]
PyJWT==2.9.0
gunicorn==23.0.0
requests==2.32.3
```

### Step 2: Environment Variables

Keep your existing environment variables in Render. The new system uses:

**Required (already set):**
- `DATABASE_URL` - PostgreSQL connection
- `SECRET_KEY` - JWT signing
- `GOOGLE_CLIENT_ID` - Google OAuth
- `GOOGLE_CLIENT_SECRET` - Google OAuth
- `RAZORPAY_KEY_ID` - Payment gateway
- `RAZORPAY_KEY_SECRET` - Payment gateway
- `RAZORPAY_WEBHOOK_SECRET` - Payment webhooks
- `RAZORPAY_MONTHLY_LINK` - Payment link (₹299/month)
- `RAZORPAY_QUARTERLY_LINK` - Payment link (₹699/quarter)
- `RAZORPAY_YEARLY_LINK` - Payment link (₹1999/year)
- `ADMIN_EMAILS` - Comma-separated analyst emails

**Removed (no longer needed):**
- `GROK_API_KEY` - Not used
- `SMTP_USER` / `SMTP_PASS` - Email notifications removed
- `FRONTEND_URL` - Not needed

### Step 3: Update Google OAuth

In your `index.html`, replace this line with your actual Google Client ID:

```javascript
// Line 474
client_id: 'YOUR_GOOGLE_CLIENT_ID', // Replace with actual client ID
```

Get your Client ID from: https://console.cloud.google.com/apis/credentials

### Step 4: Deploy to Render

1. **Replace files** in your repository:
   ```bash
   # In your Git repository
   rm app.py index.html  # Remove old files
   
   # Copy new files
   cp /path/to/new/app.py app.py
   cp /path/to/new/index.html index.html
   cp /path/to/new/admin.html admin.html
   cp /path/to/new/requirements.txt requirements.txt
   
   git add .
   git commit -m "Revamp: Portfolio advisory model"
   git push
   ```

2. **Render will auto-deploy** (takes ~5 minutes)

3. **Database migration** happens automatically on first deployment (new tables created)

### Step 5: Add Your First Stocks

1. Go to `https://yourdomain.com/admin.html`
2. Sign in with your admin Google account
3. Click "+ Add Stock" and fill in:
   - Symbol (e.g., RELIANCE)
   - Company Name
   - Rating: Buy / Hold / Sell
   - IRR Target: Expected return %
   - Risk Category: Low / Medium / High
   - Entry Price, Target Price
   - Thesis Summary (free preview)
   - Detailed Thesis (Pro only)

---

## 🧮 How the Portfolio Engine Works

### Risk Profile Calculation

Users answer 7 questions (0-4 points each):
1. Investment experience
2. Investment horizon
3. Volatility comfort
4. Loss reaction
5. Return expectations
6. High-risk allocation comfort
7. Market crash response

**Score → Profile:**
- 0-10 points (0-35%): **Conservative**
- 11-20 points (36-70%): **Moderate**
- 21-28 points (71-100%): **Aggressive**

### Portfolio Construction Algorithm

**Eligibility Filter:**
- Only stocks with `rating = "buy"`
- Only stocks with `irr_target >= 16%`
- Only active stocks (`is_active = true`)

**Allocation Strategy:**

| Risk Profile | Low Risk | Medium Risk | High Risk |
|-------------|----------|-------------|-----------|
| Conservative | 60% | 30% | 10% |
| Moderate | 30% | 50% | 20% |
| Aggressive | 15% | 35% | 50% |

**Selection Rules:**
1. Sort stocks by IRR (highest first) within each risk category
2. Select best stocks from each category per allocation %
3. Ensure sector diversification (max 3 stocks per sector)
4. Cap individual allocation at 15%
5. If >12 eligible stocks, pick top 12 by IRR + diversification
6. Equal-weight allocation with proportional adjustment

**Example Output:**
```
Conservative User → 7 low-risk + 4 medium-risk + 1 high-risk
Moderate User → 4 low-risk + 6 medium-risk + 2 high-risk
Aggressive User → 2 low-risk + 4 medium-risk + 6 high-risk
```

---

## 🎨 User Flow

1. **Landing Page** → User sees "What to Buy Now?" hero
2. **Click CTA** → Login with Google (if not logged in)
3. **Risk Questionnaire** → 7 questions (first-time users)
4. **Portfolio Display** → See 12 personalized stocks with:
   - Allocation %
   - IRR target
   - Entry/target prices
   - Brief thesis (free)
   - "View Full Thesis" button (requires Pro)
5. **Upgrade Prompt** → Subscribe to Pro for detailed analysis

---

## 👨‍💼 Admin Workflow

### Weekly Routine:

1. **Update Ratings** (Weekly)
   - Review all 50 stocks
   - Change ratings: Buy → Hold or Hold → Buy
   - Update IRR targets based on latest analysis

2. **Add New Stocks** (As needed)
   - Research new opportunities
   - Add to watchlist (target: maintain 50 stocks)
   - Write thesis summary + detailed analysis

3. **Remove Stale Stocks** (Monthly)
   - Mark as inactive: `is_active = false`
   - Or delete permanently

4. **Monitor Portfolio Performance**
   - Check how many users got each stock
   - Review feedback from Pro subscribers

---

## 🔐 Access Control

### Free Users (No Subscription)
- ✅ Risk questionnaire
- ✅ Portfolio recommendations (12 stocks)
- ✅ Basic details (symbol, allocation, IRR, entry/target)
- ✅ Brief thesis summary
- ❌ Detailed thesis
- ❌ Analyst notes
- ❌ Team discussions

### Pro Users (Paid Subscription)
- ✅ Everything from Free
- ✅ Full detailed thesis
- ✅ Analyst notes & rationale
- ✅ Holding period recommendations
- ✅ Risk analysis
- ✅ Team discussion access

---

## 💳 Subscription Plans

| Plan | Price | Duration | Discount |
|------|-------|----------|----------|
| Monthly | ₹299 | 30 days | — |
| Quarterly | ₹699 | 90 days | 22% (₹198 saved) |
| Yearly | ₹1,999 | 365 days | 44% (₹1,589 saved) |

**Payment Flow:**
1. User clicks "Upgrade to Pro"
2. Modal shows 3 plan options
3. Click subscribe → Opens Razorpay payment link
4. After payment → Webhook activates subscription
5. User immediately gets Pro access

---

## 📊 Database Schema

### New Tables:

**users**
- id, email, name, picture (Google OAuth)
- subscription_status: free / active / expired
- subscription_plan: monthly / quarterly / yearly
- subscription_start, subscription_end
- risk_profile: conservative / moderate / aggressive
- risk_score: 0-100
- risk_questionnaire: JSON (user answers)

**stocks** (Analyst Watchlist)
- id, symbol, name
- rating: buy / hold / sell
- irr_target: Expected IRR %
- risk_category: low / medium / high
- market_cap, sector
- thesis_summary: Brief (free)
- thesis_detailed: Full (Pro only)
- holding_period: 1-2 years, 2-3 years, etc.
- entry_price, target_price, stop_loss
- analyst_notes: Internal team notes
- is_active: true / false
- updated_at: Last modified timestamp

**portfolio_recommendations**
- id, user_id
- stocks: JSON array of {symbol, allocation%, reason}
- risk_profile
- created_at

---

## 🐛 Troubleshooting

### Issue: "Admin access required" error
**Solution:** Add your email to `ADMIN_EMAILS` env var in Render:
```
ADMIN_EMAILS=analyst1@team.com,analyst2@team.com
```

### Issue: Google login not working
**Solution:** 
1. Check `GOOGLE_CLIENT_ID` is set in Render
2. Update `client_id` in index.html line 474
3. Add your domain to Google Console authorized domains

### Issue: Portfolio shows "No stocks available"
**Solution:** 
1. Go to admin dashboard
2. Add at least 12 stocks with:
   - rating = "buy"
   - irr_target >= 16%
   - is_active = true

### Issue: Payment webhook not activating subscription
**Solution:**
1. Verify `RAZORPAY_WEBHOOK_SECRET` matches Razorpay dashboard
2. Check webhook URL in Razorpay: `https://yourdomain.com/api/payment/webhook`
3. Ensure webhook includes customer email

---

## 📈 Next Steps & Enhancements

### Phase 2 (Optional):
1. **Email Notifications**
   - Portfolio updates when analysts change ratings
   - Weekly newsletter with market insights

2. **Portfolio Tracking**
   - Let users input how much they invested
   - Track actual vs target performance
   - Send alerts when price hits targets

3. **Research Reports**
   - Publish weekly market commentary
   - Sector deep-dives
   - Macro analysis

4. **Mobile App**
   - React Native app
   - Push notifications for portfolio updates

---

## 🆘 Support

Need help? Contact:
- **Technical Issues:** Check Render logs
- **Database Issues:** Connect via `render psql diy-db`
- **API Errors:** Check `https://yourdomain.com/api/data-status`

---

## ✅ Pre-Launch Checklist

Before going live:

- [ ] Replace `YOUR_GOOGLE_CLIENT_ID` in index.html
- [ ] Set all environment variables in Render
- [ ] Add yourself to `ADMIN_EMAILS`
- [ ] Test login flow end-to-end
- [ ] Add 15-20 stocks in admin dashboard
- [ ] Test risk questionnaire
- [ ] Verify portfolio generation works
- [ ] Test payment flow with Razorpay test mode
- [ ] Update domain in Google OAuth console
- [ ] Add domain to Razorpay webhook settings

---

## 🎉 You're Ready!

Your portfolio advisory platform is now live. Here's what users see:

1. **Clean landing page** with clear value proposition
2. **Simple risk assessment** (7 questions, 2 minutes)
3. **Instant portfolio** (12 stocks, personalized)
4. **Transparent pricing** (₹299-1999)
5. **Professional experience** throughout

Your team can now:
- Manage 50-stock watchlist via admin dashboard
- Update ratings weekly
- Write detailed thesis for Pro subscribers
- Track user growth and subscription metrics

Good luck! 🚀
