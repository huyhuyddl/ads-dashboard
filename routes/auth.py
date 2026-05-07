"""
routes/auth.py — Blueprint xử lý đăng nhập / đăng xuất
"""
from flask import Blueprint, request, jsonify, session, redirect, url_for
from models.user import get_user_by_credentials, update_last_login
from models.activity import log_activity

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/api/login")
def api_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Vui lòng nhập đầy đủ thông tin"}), 400

    user = get_user_by_credentials(username, password)
    if not user:
        return jsonify({"error": "Sai tài khoản hoặc mật khẩu"}), 401

    session.update({
        "user_id":  user["id"],
        "username": user["username"],
        "role":     user["role"],
    })
    update_last_login(user["id"])
    log_activity(user["id"], "LOGIN", "Đăng nhập thành công")

    return jsonify({"role": user["role"], "username": user["username"]})


@auth_bp.post("/api/logout")
def api_logout():
    uid = session.get("user_id")
    if uid:
        log_activity(uid, "LOGOUT", "Đăng xuất")
    session.clear()
    return jsonify({"ok": True})
