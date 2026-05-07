"""
routes/admin.py — Blueprint cho admin panel
"""
from flask import Blueprint, request, jsonify, session
from functools import wraps
import pymysql.err

from models.user import (
    get_all_users, toggle_user_active, create_user,
    change_user_role, get_admin_stats,
)
from models.activity import log_activity, get_logs
from services.platform_data import build_dashboard_response

admin_bp = Blueprint("admin", __name__)


# ── Decorators ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Users ──────────────────────────────────────────────────────────────────

@admin_bp.get("/api/admin/users")
@admin_required
def api_admin_users():
    return jsonify(get_all_users())


@admin_bp.post("/api/admin/users")
@admin_required
def api_create_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "user")

    if not username or not email or not password:
        return jsonify({"error": "Thiếu thông tin bắt buộc"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu tối thiểu 6 ký tự"}), 400

    try:
        create_user(username, email, password, role)
        log_activity(session["user_id"], "CREATE_USER", f"Tạo user {username}")
        return jsonify({"ok": True})
    except pymysql.err.IntegrityError:
        return jsonify({"error": "Username hoặc email đã tồn tại"}), 400


@admin_bp.post("/api/admin/users/<int:uid>/toggle")
@admin_required
def api_toggle_user(uid: int):
    try:
        new_status = toggle_user_active(uid)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    action_lbl = "Mở khóa" if new_status else "Khóa"
    log_activity(session["user_id"], "TOGGLE_USER", f"{action_lbl} user #{uid}")
    return jsonify({"is_active": new_status})


@admin_bp.post("/api/admin/users/<int:uid>/role")
@admin_required
def api_change_role(uid: int):
    role = (request.json or {}).get("role")
    if role not in ("admin", "user"):
        return jsonify({"error": "Invalid role"}), 400
    change_user_role(uid, role)
    log_activity(session["user_id"], "CHANGE_ROLE", f"Đổi role user #{uid} → {role}")
    return jsonify({"ok": True})


# ── Logs ───────────────────────────────────────────────────────────────────

@admin_bp.get("/api/admin/logs")
@admin_required
def api_admin_logs():
    uid = request.args.get("user_id", type=int)
    return jsonify(get_logs(user_id=uid))


# ── Stats ──────────────────────────────────────────────────────────────────

@admin_bp.get("/api/admin/stats")
@admin_required
def api_admin_stats():
    stats = get_admin_stats()
    # Tổng chi phí từ mock data (user id 2→4)
    total_spend = sum(
        build_dashboard_response(i, "all", 30, force_mock=True)["total_spend"]
        for i in range(2, 5)
    )
    stats["total_spend"] = total_spend
    return jsonify(stats)


# ── Dashboard preview ──────────────────────────────────────────────────────

@admin_bp.get("/api/admin/preview-dashboard")
@admin_required
def api_admin_preview_dashboard():
    uid  = request.args.get("user_id", type=int)
    days = int(request.args.get("days", 7))
    if not uid:
        return jsonify({"error": "Missing user_id"}), 400

    # Dùng force_mock=True vì admin preview luôn dùng mock
    data = build_dashboard_response(uid, "all", days, force_mock=True)
    log_activity(session["user_id"], "VIEW_DASHBOARD", f"Admin preview user #{uid}")
    return jsonify(data)
