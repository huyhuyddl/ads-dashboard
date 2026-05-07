"""
database.py — Khởi tạo MySQL database, tables và seed dữ liệu mẫu
Chạy độc lập hoặc gọi từ app.py khi start.
"""
import pymysql
import pymysql.cursors
from datetime import datetime
from models.user import hash_pw
import config
from extensions import logger


def init_db() -> None:
    """Tạo database + tables + seed data nếu chưa tồn tại."""

    # 1. Tạo database nếu chưa có
    tmp = pymysql.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        charset="utf8mb4",
    )
    with tmp.cursor() as c:
        c.execute(
            f"CREATE DATABASE IF NOT EXISTS `{config.MYSQL_DB}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
    tmp.commit()
    tmp.close()
    logger.info("Database `%s` ensured.", config.MYSQL_DB)

    # 2. Tạo tables
    conn = pymysql.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        database=config.MYSQL_DB,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )
    with conn.cursor() as c:

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                username    VARCHAR(100) UNIQUE NOT NULL,
                email       VARCHAR(200) UNIQUE NOT NULL,
                password    VARCHAR(256) NOT NULL,
                role        VARCHAR(20)  DEFAULT 'user',
                is_active   TINYINT      DEFAULT 1,
                created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
                last_login  DATETIME
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS platform_connections (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                user_id       INT         NOT NULL,
                platform      VARCHAR(50) NOT NULL,
                access_token  TEXT,
                refresh_token TEXT,
                expires_at    DATETIME,
                account_id    VARCHAR(200),
                account_name  VARCHAR(200),
                scopes        TEXT,
                is_active     TINYINT  DEFAULT 1,
                connected_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_synced   DATETIME,
                UNIQUE KEY uq_user_platform (user_id, platform),
                FOREIGN KEY (user_id) REFERENCES users(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id         INT AUTO_INCREMENT PRIMARY KEY,
                user_id    INT,
                action     VARCHAR(100),
                detail     TEXT,
                ip         VARCHAR(50),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS budgets (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                user_id       INT,
                platform      VARCHAR(50),
                monthly_limit DOUBLE,
                month         VARCHAR(7),
                UNIQUE KEY uq_budget (user_id, platform, month),
                FOREIGN KEY (user_id) REFERENCES users(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS metrics_history (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                user_id     INT         NOT NULL,
                platform    VARCHAR(50) NOT NULL,
                date        DATE        NOT NULL,
                spend       DOUBLE      DEFAULT 0,
                revenue     DOUBLE      DEFAULT 0,
                clicks      INT         DEFAULT 0,
                impressions INT         DEFAULT 0,
                roas        DOUBLE      DEFAULT 0,
                synced_at   DATETIME    DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uq_user_platform_date (user_id, platform, date),
                FOREIGN KEY (user_id) REFERENCES users(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # ── Seed users ────────────────────────────────────────────────
        seed_users = [
            ("admin",        "admin@ads.com",       hash_pw("admin123"), "admin"),
            ("nguyen_van_a", "vana@company.com",     hash_pw("user123"),  "user"),
            ("tran_thi_b",   "thib@agency.com",      hash_pw("user123"),  "user"),
            ("le_van_c",     "vanc@shop.com",         hash_pw("user123"),  "user"),
        ]
        for u in seed_users:
            c.execute(
                "INSERT IGNORE INTO users (username, email, password, role) VALUES (%s,%s,%s,%s)", u
            )

        # ── Seed budgets ──────────────────────────────────────────────
        month = datetime.now().strftime("%Y-%m")
        seed_budgets = [
            # nguyen_van_a (id=2) — dùng cả 3 platform
            (2, "facebook", 50_000_000, month),
            (2, "google",   50_000_000, month),
            (2, "tiktok",   17_000_000, month),
            # tran_thi_b (id=3) — agency, ngân sách cao
            (3, "facebook", 30_000_000, month),
            (3, "google",   20_000_000, month),
            # le_van_c (id=4) — shop nhỏ, chỉ FB + TikTok
            (4, "facebook", 25_000_000, month),
            (4, "tiktok",   10_000_000, month),
        ]
        for b in seed_budgets:
            c.execute(
                "INSERT IGNORE INTO budgets (user_id, platform, monthly_limit, month) VALUES (%s,%s,%s,%s)", b
            )

    conn.commit()
    conn.close()
    logger.info("Database initialized — tables & seed data OK.")


if __name__ == "__main__":
    init_db()
    print("Done.")