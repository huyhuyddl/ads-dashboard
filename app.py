"""
app.py — Entry point của AdsAnalytics Pro
Chỉ chứa: khởi tạo Flask, đăng ký blueprints, chạy server.
Logic nghiệp vụ nằm trong models/, services/, routes/.
"""
import os
from flask import Flask

import config
from extensions import logger
from database import init_db

# ── Blueprints ─────────────────────────────────────────────────────────────
from routes.pages     import pages_bp
from routes.auth      import auth_bp
from routes.dashboard import dashboard_bp
from routes.oauth     import oauth_bp
from routes.admin     import admin_bp


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.secret_key = config.SECRET_KEY

    # Đăng ký tất cả blueprints
    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(oauth_bp)
    app.register_blueprint(admin_bp)

    logger.info("Flask app created — blueprints registered.")
    return app


if __name__ == "__main__":
    os.makedirs("instance", exist_ok=True)
    init_db()

    application = create_app()
    application.run(
        debug=config.DEBUG,
        port=config.PORT,
    )
