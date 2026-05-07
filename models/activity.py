"""
models/activity.py — Ghi và đọc activity_logs
"""
from flask import request
from extensions import get_db
from extensions import logger


def log_activity(user_id: int, action: str, detail: str = "") -> None:
    try:
        ip = request.remote_addr
    except RuntimeError:
        ip = "system"
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "INSERT INTO activity_logs (user_id, action, detail, ip) VALUES (%s,%s,%s,%s)",
                (user_id, action, detail, ip),
            )
        conn.commit()
    except Exception as e:
        logger.error("log_activity error: %s", e)
    finally:
        conn.close()


def get_logs(user_id: int | None = None, limit: int = 200) -> list[dict]:
    conn = get_db()
    try:
        with conn.cursor() as c:
            if user_id:
                c.execute(
                    "SELECT l.*, u.username FROM activity_logs l "
                    "JOIN users u ON l.user_id=u.id "
                    "WHERE l.user_id=%s ORDER BY l.created_at DESC LIMIT %s",
                    (user_id, min(limit, 100)),
                )
            else:
                c.execute(
                    "SELECT l.*, u.username FROM activity_logs l "
                    "JOIN users u ON l.user_id=u.id "
                    "ORDER BY l.created_at DESC LIMIT %s",
                    (limit,),
                )
            logs = c.fetchall()
        for log in logs:
            if log.get("created_at") and not isinstance(log["created_at"], str):
                log["created_at"] = str(log["created_at"])
        return logs
    finally:
        conn.close()
