"""
routes/dashboard.py — Blueprint cho dashboard data và connections
"""
from flask import Blueprint, request, jsonify, session
from functools import wraps
from models.connection import (
    get_connections, disconnect_platform,
    token_expired, get_days_left, format_expires,
)
from models.activity import log_activity
from services.platform_data import build_dashboard_response
import config

dashboard_bp = Blueprint("dashboard", __name__)


# ── Decorator ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Dashboard data ─────────────────────────────────────────────────────────

@dashboard_bp.get("/api/dashboard-data")
@login_required
def api_dashboard_data():
    """
    Route tổng hợp cho dashboard.html.
    Params: ?days=7|30|90 &platform=all|facebook|google|tiktok &force_mock=0|1
    """
    days       = int(request.args.get("days", 7))
    platform   = request.args.get("platform", "all")
    force_mock = request.args.get("force_mock", "0") == "1"
    uid        = session["user_id"]

    if platform not in ("all", *config.PLATFORMS):
        return jsonify({"error": "Invalid platform"}), 400

    data = build_dashboard_response(uid, platform, days, force_mock)
    log_activity(uid, "VIEW_DASHBOARD", f"platform={platform} days={days} mock={force_mock}")
    return jsonify(data)


# ── Legacy route (giữ backward-compat với code cũ nếu còn) ────────────────

@dashboard_bp.get("/api/dashboard/<platform>")
@login_required
def api_dashboard_platform(platform):
    if platform not in ("all", *config.PLATFORMS):
        return jsonify({"error": "Invalid platform"}), 400
    days       = int(request.args.get("days", 7))
    force_mock = request.args.get("force_mock", "0") == "1"
    uid        = session["user_id"]
    data       = build_dashboard_response(uid, platform, days, force_mock)
    log_activity(uid, "VIEW_DASHBOARD", f"tab={platform} days={days}")
    return jsonify(data)


# ── Connections ────────────────────────────────────────────────────────────

def _build_connections_response(uid: int) -> dict:
    connections = get_connections(uid)
    can_connect = {
        "facebook": bool(config.FB_APP_ID and config.FB_APP_SECRET),
        "google":   bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET),
        "tiktok":   bool(config.TIKTOK_APP_ID and config.TIKTOK_APP_SECRET),
    }
    result = {}
    for p in config.PLATFORMS:
        if p in connections:
            row = connections[p]
            result[p] = {
                "connected":    True,
                "can_connect":  can_connect[p],
                "account_name": row.get("account_name", ""),
                "account_id":   row.get("account_id", ""),
                "expires":      format_expires(row),
                "days_left":    get_days_left(row),
                "needs_reauth": token_expired(row),
                "last_synced":  str(row["last_synced"]) if row.get("last_synced") else None,
            }
        else:
            result[p] = {"connected": False, "can_connect": can_connect[p]}
    return result


@dashboard_bp.get("/api/connections")
@login_required
def api_connections():
    return jsonify(_build_connections_response(session["user_id"]))


@dashboard_bp.get("/api/connections/status")
@login_required
def api_connections_status():
    """Shortcut cho sidebar — giống /api/connections nhưng ít field hơn."""
    uid = session["user_id"]
    connections = get_connections(uid)
    can_connect = {
        "facebook": bool(config.FB_APP_ID and config.FB_APP_SECRET),
        "google":   bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET),
        "tiktok":   bool(config.TIKTOK_APP_ID and config.TIKTOK_APP_SECRET),
    }
    result = {}
    for p in config.PLATFORMS:
        if p in connections:
            row = connections[p]
            result[p] = {
                "connected":    True,
                "can_connect":  can_connect[p],
                "account_name": row.get("account_name", ""),
                "account_id":   row.get("account_id", ""),
                "days_left":    get_days_left(row),
                "needs_reauth": token_expired(row),
                "last_synced":  str(row["last_synced"]) if row.get("last_synced") else None,
            }
        else:
            result[p] = {"connected": False, "can_connect": can_connect[p]}
    return jsonify(result)


@dashboard_bp.post("/api/disconnect/<platform>")
@login_required
def api_disconnect(platform):
    if platform not in config.PLATFORMS:
        return jsonify({"error": "Invalid platform"}), 400
    uid = session["user_id"]
    disconnect_platform(uid, platform)
    log_activity(uid, "DISCONNECT_PLATFORM", f"Ngắt kết nối {platform}")
    return jsonify({"ok": True})
