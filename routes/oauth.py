"""
routes/oauth.py — OAuth flow cho Facebook, Google, TikTok
"""
import json
import secrets
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from flask import Blueprint, request, session, redirect, url_for, jsonify
from functools import wraps

import config
from models.connection import save_connection
from models.activity import log_activity
from services.facebook import fb_to_long_lived, _http_get, _http_post

oauth_bp = Blueprint("oauth", __name__)


# ── Decorator ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("pages.login_page"))
        return f(*args, **kwargs)
    return decorated


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _post(url, data, timeout=10):
    p = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=p, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ══════════════════════════════════════════════════════════════════════════
# FACEBOOK
# ══════════════════════════════════════════════════════════════════════════

@oauth_bp.get("/auth/facebook")
@login_required
def auth_facebook():
    if not config.FB_APP_ID:
        return jsonify({"error": "FB_APP_ID chưa cấu hình trong .env"}), 503
    state = secrets.token_urlsafe(16)
    session["oauth_state_fb"] = state
    params = urllib.parse.urlencode({
        "client_id":     config.FB_APP_ID,
        "redirect_uri":  f"{config.APP_BASE_URL}/auth/facebook/callback",
        "scope":         config.FB_SCOPES,
        "state":         state,
        "response_type": "code",
    })
    return redirect(f"{config.FB_AUTH_URL}?{params}")


@oauth_bp.get("/auth/facebook/callback")
@login_required
def auth_facebook_callback():
    if request.args.get("state") != session.pop("oauth_state_fb", None):
        return redirect(url_for("pages.dashboard_page") + "?error=invalid_state")
    error = request.args.get("error")
    if error:
        return redirect(url_for("pages.dashboard_page") + f"?error={error}")
    code = request.args.get("code")
    if not code:
        return redirect(url_for("pages.dashboard_page") + "?error=no_code")
    try:
        params = urllib.parse.urlencode({
            "client_id":     config.FB_APP_ID,
            "client_secret": config.FB_APP_SECRET,
            "redirect_uri":  f"{config.APP_BASE_URL}/auth/facebook/callback",
            "code":          code,
        })
        short    = _get(f"{config.FB_TOKEN_URL}?{params}")["access_token"]
        long_tok, expires_at = fb_to_long_lived(short)
        me       = _get(f"{config.FB_API}/me?fields=id,name&access_token={long_tok}")
        accounts = _get(f"{config.FB_API}/me/adaccounts?fields=id,name,account_status&access_token={long_tok}")
        ad_list  = accounts.get("data", [])
        active   = next((a for a in ad_list if a.get("account_status") == 1), ad_list[0] if ad_list else None)
        account_id   = active["id"]           if active else ""
        account_name = active.get("name", "") if active else me.get("name", "")
        save_connection(
            session["user_id"], "facebook", long_tok, None, expires_at,
            account_id, account_name, json.dumps(config.FB_SCOPES.split(",")),
        )
        log_activity(session["user_id"], "CONNECT_PLATFORM", f"Facebook: {account_name} ({account_id})")
        return redirect(url_for("pages.dashboard_page") + "?connected=facebook")
    except Exception as e:
        from extensions import logger
        logger.error("FB OAuth callback error: %s", e)
        return redirect(url_for("pages.dashboard_page") + "?error=fb_oauth_failed")


# ══════════════════════════════════════════════════════════════════════════
# GOOGLE
# ══════════════════════════════════════════════════════════════════════════

@oauth_bp.get("/auth/google")
@login_required
def auth_google():
    if not config.GOOGLE_CLIENT_ID:
        return jsonify({
            "error": "Chưa cấu hình",
            "guide": "Tạo tại console.cloud.google.com → APIs & Services → OAuth 2.0 Client ID. "
                     "Thêm GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET vào .env",
        }), 503
    state = secrets.token_urlsafe(16)
    session["oauth_state_google"] = state
    params = urllib.parse.urlencode({
        "client_id":     config.GOOGLE_CLIENT_ID,
        "redirect_uri":  f"{config.APP_BASE_URL}/auth/google/callback",
        "scope":         config.GOOGLE_SCOPES,
        "state":         state,
        "response_type": "code",
        "access_type":   "offline",
        "prompt":        "consent",
    })
    return redirect(f"{config.GOOGLE_AUTH_URL}?{params}")


@oauth_bp.get("/auth/google/callback")
@login_required
def auth_google_callback():
    if request.args.get("state") != session.pop("oauth_state_google", None):
        return redirect(url_for("pages.dashboard_page") + "?error=invalid_state")
    code = request.args.get("code")
    if not code:
        return redirect(url_for("pages.dashboard_page") + f"?error={request.args.get('error','no_code')}")
    try:
        d = _post(config.GOOGLE_TOKEN_URL, {
            "code":          code,
            "client_id":     config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "redirect_uri":  f"{config.APP_BASE_URL}/auth/google/callback",
            "grant_type":    "authorization_code",
        })
        exp = (datetime.now() + timedelta(seconds=d.get("expires_in", 3600))).isoformat()
        save_connection(
            session["user_id"], "google",
            d["access_token"], d.get("refresh_token", ""),
            exp, "TODO_CUSTOMER_ID", "Google Ads Account",
        )
        log_activity(session["user_id"], "CONNECT_PLATFORM", "Google Ads OK")
        return redirect(url_for("pages.dashboard_page") + "?connected=google")
    except Exception as e:
        from extensions import logger
        logger.error("Google OAuth callback error: %s", e)
        return redirect(url_for("pages.dashboard_page") + "?error=google_oauth_failed")


# ══════════════════════════════════════════════════════════════════════════
# TIKTOK
# ══════════════════════════════════════════════════════════════════════════

@oauth_bp.get("/auth/tiktok")
@login_required
def auth_tiktok():
    if not config.TIKTOK_APP_ID:
        return jsonify({
            "error": "Chưa cấu hình",
            "guide": "Tạo tại business.tiktok.com/portal/apps → Marketing API. "
                     "Thêm TIKTOK_APP_ID + TIKTOK_APP_SECRET vào .env",
        }), 503
    state = secrets.token_urlsafe(16)
    session["oauth_state_tiktok"] = state
    params = urllib.parse.urlencode({
        "app_id":       config.TIKTOK_APP_ID,
        "redirect_uri": f"{config.APP_BASE_URL}/auth/tiktok/callback",
        "state":        state,
    })
    return redirect(f"{config.TIKTOK_AUTH_URL}?{params}")


@oauth_bp.get("/auth/tiktok/callback")
@login_required
def auth_tiktok_callback():
    if request.args.get("state") != session.pop("oauth_state_tiktok", None):
        return redirect(url_for("pages.dashboard_page") + "?error=invalid_state")
    code = request.args.get("auth_code") or request.args.get("code")
    if not code:
        return redirect(url_for("pages.dashboard_page") + "?error=no_code")
    try:
        d = _post(config.TIKTOK_TOKEN_URL, {
            "app_id":    config.TIKTOK_APP_ID,
            "secret":    config.TIKTOK_APP_SECRET,
            "auth_code": code,
        }).get("data", {})
        exp = (datetime.now() + timedelta(
            seconds=d.get("access_token_expire_in", 7_776_000)
        )).isoformat()
        save_connection(
            session["user_id"], "tiktok",
            d["access_token"], d.get("refresh_token", ""),
            exp, str(d.get("advertiser_id", "")), "TikTok Ads Account",
        )
        log_activity(session["user_id"], "CONNECT_PLATFORM", "TikTok Ads OK")
        return redirect(url_for("pages.dashboard_page") + "?connected=tiktok")
    except Exception as e:
        from extensions import logger
        logger.error("TikTok OAuth callback error: %s", e)
        return redirect(url_for("pages.dashboard_page") + "?error=tiktok_oauth_failed")
