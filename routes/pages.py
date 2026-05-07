"""
routes/pages.py — Blueprint cho các route trả về HTML (Jinja2 templates)
"""
from flask import Blueprint, render_template, session, redirect, url_for
from functools import wraps

pages_bp = Blueprint("pages", __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("pages.login_page"))
        return f(*args, **kwargs)
    return decorated


@pages_bp.get("/")
def index():
    if "user_id" in session:
        return redirect(
            url_for("pages.admin_page")
            if session.get("role") == "admin"
            else url_for("pages.dashboard_page")
        )
    return redirect(url_for("pages.login_page"))


@pages_bp.get("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("pages.index"))
    return render_template("login.html")


@pages_bp.get("/dashboard")
@login_required
def dashboard_page():
    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
    )


@pages_bp.get("/admin")
@login_required
def admin_page():
    if session.get("role") != "admin":
        return redirect(url_for("pages.dashboard_page"))
    return render_template("admin.html", username=session["username"])
