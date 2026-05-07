"""
config.py — Tập trung toàn bộ cấu hình từ .env
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Flask ──────────────────────────────────────────────────────────────────
SECRET_KEY   = os.getenv("SECRET_KEY", "ads-dashboard-secret-2024")
DEBUG        = os.getenv("DEBUG", "true").lower() == "true"
PORT         = int(os.getenv("PORT", 5000))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5000")

# ── MySQL ──────────────────────────────────────────────────────────────────
MYSQL_HOST     = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT     = int(os.getenv("MYSQL_PORT", 3306))
MYSQL_USER     = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "P@ssw0rd")
MYSQL_DB       = os.getenv("MYSQL_DB", "ads_dashboard")
MYSQL_POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", 10))

# ── Facebook OAuth ─────────────────────────────────────────────────────────
FB_APP_ID     = os.getenv("FB_APP_ID", "")
FB_APP_SECRET = os.getenv("FB_APP_SECRET", "")
FB_SCOPES     = "ads_read,ads_management,read_insights"
FB_AUTH_URL   = "https://www.facebook.com/v18.0/dialog/oauth"
FB_TOKEN_URL  = "https://graph.facebook.com/v18.0/oauth/access_token"
FB_API        = "https://graph.facebook.com/v18.0"

# ── Google OAuth ───────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_AUTH_URL      = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES        = "https://www.googleapis.com/auth/adwords"

# ── TikTok OAuth ───────────────────────────────────────────────────────────
TIKTOK_APP_ID     = os.getenv("TIKTOK_APP_ID", "")
TIKTOK_APP_SECRET = os.getenv("TIKTOK_APP_SECRET", "")
TIKTOK_AUTH_URL   = "https://business-api.tiktok.com/portal/auth"
TIKTOK_TOKEN_URL  = "https://business-api.tiktok.com/open_api/v1.3/oauth2/access_token/"

# ── Business logic ─────────────────────────────────────────────────────────
# Tỷ giá USD → VND (cập nhật theo thực tế hoặc dùng API tỷ giá)
USD_TO_VND = float(os.getenv("USD_TO_VND", 23_000))

# Ngưỡng cảnh báo budget (%)
BUDGET_WARN_PCT   = 70
BUDGET_DANGER_PCT = 85

# Token sắp hết hạn (ngày)
TOKEN_EXPIRING_DAYS = 7

# Mock data config theo platform
MOCK_CFG = {
    "facebook": {"base": 6_200_000, "roas": 3.1},
    "google":   {"base": 4_500_000, "roas": 4.2},
    "tiktok":   {"base": 1_800_000, "roas": 3.8},
}

PLATFORMS = ["facebook", "google", "tiktok"]
