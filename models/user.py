"""
models/user.py — CRUD cho bảng users
"""
import hashlib
from datetime import datetime
from extensions import get_db
from extensions import logger


def hash_pw(pw: str) -> str:
    """SHA-256 hash password. TODO: nâng lên bcrypt."""
    return hashlib.sha256(pw.encode()).hexdigest()


def get_user_by_credentials(username: str, password: str) -> dict | None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "SELECT * FROM users WHERE username=%s AND password=%s AND is_active=1",
                (username, hash_pw(password)),
            )
            return c.fetchone()
    finally:
        conn.close()


def get_user_by_id(uid: int) -> dict | None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute("SELECT * FROM users WHERE id=%s", (uid,))
            return c.fetchone()
    finally:
        conn.close()


def update_last_login(uid: int) -> None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "UPDATE users SET last_login=%s WHERE id=%s",
                (datetime.now().isoformat(), uid),
            )
        conn.commit()
    finally:
        conn.close()


def get_all_users() -> list[dict]:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "SELECT id, username, email, role, is_active, created_at, last_login "
                "FROM users ORDER BY id"
            )
            users = c.fetchall()
            for u in users:
                # Serialize datetime
                for key in ("created_at", "last_login"):
                    if u.get(key) and not isinstance(u[key], str):
                        u[key] = str(u[key])
                # Lấy platform connections
                c.execute(
                    "SELECT platform, account_name, is_active, last_synced "
                    "FROM platform_connections WHERE user_id=%s",
                    (u["id"],),
                )
                platforms = c.fetchall()
                for p in platforms:
                    if p.get("last_synced") and not isinstance(p["last_synced"], str):
                        p["last_synced"] = str(p["last_synced"])
                u["platforms"] = platforms
        return users
    finally:
        conn.close()


def toggle_user_active(uid: int) -> int:
    """Toggle is_active. Trả về giá trị mới."""
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute("SELECT is_active FROM users WHERE id=%s", (uid,))
            row = c.fetchone()
            if not row:
                raise ValueError(f"User #{uid} not found")
            new_status = 0 if row["is_active"] else 1
            c.execute(
                "UPDATE users SET is_active=%s WHERE id=%s",
                (new_status, uid),
            )
        conn.commit()
        return new_status
    finally:
        conn.close()


def create_user(username: str, email: str, password: str, role: str = "user") -> None:
    """Raises pymysql.err.IntegrityError nếu username/email trùng."""
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "INSERT INTO users (username, email, password, role) VALUES (%s,%s,%s,%s)",
                (username, email, hash_pw(password), role),
            )
        conn.commit()
        logger.info("Created user: %s (%s)", username, role)
    finally:
        conn.close()


def change_user_role(uid: int, role: str) -> None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute("UPDATE users SET role=%s WHERE id=%s", (role, uid))
        conn.commit()
        logger.info("Changed role of user #%d → %s", uid, role)
    finally:
        conn.close()


def get_admin_stats() -> dict:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute('SELECT COUNT(*) AS c FROM users WHERE role="user"')
            total = c.fetchone()["c"]
            c.execute('SELECT COUNT(*) AS c FROM users WHERE role="user" AND is_active=1')
            active = c.fetchone()["c"]
            c.execute(
                'SELECT COUNT(*) AS c FROM activity_logs '
                'WHERE action="LOGIN" AND DATE(created_at)=CURDATE()'
            )
            today_logins = c.fetchone()["c"]
            c.execute(
                "SELECT COUNT(*) AS c FROM platform_connections WHERE is_active=1"
            )
            total_connections = c.fetchone()["c"]
        return {
            "total_users":       total,
            "active_users":      active,
            "today_logins":      today_logins,
            "total_connections": total_connections,
        }
    finally:
        conn.close()
