"""
models/connection.py — CRUD cho bảng platform_connections
"""
from datetime import datetime, timedelta
from extensions import get_db
from extensions import logger
import config


def get_connections(user_id: int) -> dict:
    """Trả về dict {platform: row} cho các connection đang active."""
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "SELECT * FROM platform_connections WHERE user_id=%s AND is_active=1",
                (user_id,),
            )
            rows = c.fetchall()
        return {r["platform"]: r for r in rows}
    finally:
        conn.close()


def save_connection(
    uid: int,
    platform: str,
    access_token: str,
    refresh_token: str | None,
    expires_at: str | None,
    account_id: str,
    account_name: str,
    scopes: str = "[]",
) -> None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                """
                INSERT INTO platform_connections
                  (user_id, platform, access_token, refresh_token, expires_at,
                   account_id, account_name, scopes, is_active, connected_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,1,NOW())
                ON DUPLICATE KEY UPDATE
                  access_token  = VALUES(access_token),
                  refresh_token = VALUES(refresh_token),
                  expires_at    = VALUES(expires_at),
                  account_id    = VALUES(account_id),
                  account_name  = VALUES(account_name),
                  scopes        = VALUES(scopes),
                  is_active     = 1,
                  connected_at  = NOW()
                """,
                (uid, platform, access_token, refresh_token, expires_at,
                 account_id, account_name, scopes),
            )
        conn.commit()
        logger.info("Saved connection: user=%d platform=%s account=%s", uid, platform, account_name)
    finally:
        conn.close()


def disconnect_platform(uid: int, platform: str) -> None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "UPDATE platform_connections SET is_active=0 WHERE user_id=%s AND platform=%s",
                (uid, platform),
            )
        conn.commit()
        logger.info("Disconnected: user=%d platform=%s", uid, platform)
    finally:
        conn.close()


def mark_last_synced(uid: int, platform: str) -> None:
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "UPDATE platform_connections SET last_synced=%s WHERE user_id=%s AND platform=%s",
                (datetime.now().isoformat(), uid, platform),
            )
        conn.commit()
    finally:
        conn.close()


def deactivate_connection(uid: int, platform: str) -> None:
    """Đánh dấu connection không còn active (token hết hạn không thể refresh)."""
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "UPDATE platform_connections SET is_active=0 WHERE user_id=%s AND platform=%s",
                (uid, platform),
            )
        conn.commit()
    finally:
        conn.close()


# ── Token helpers ──────────────────────────────────────────────────────────

def _parse_expires(row: dict) -> datetime | None:
    exp = row.get("expires_at")
    if not exp:
        return None
    if isinstance(exp, datetime):
        return exp
    try:
        return datetime.fromisoformat(str(exp))
    except Exception:
        return None


def token_expired(row: dict) -> bool:
    exp = _parse_expires(row)
    return bool(exp and datetime.now() > exp)


def token_expiring(row: dict, days: int = None) -> bool:
    if days is None:
        days = config.TOKEN_EXPIRING_DAYS
    exp = _parse_expires(row)
    return bool(exp and datetime.now() > exp - timedelta(days=days))


def get_days_left(row: dict) -> int | None:
    exp = _parse_expires(row)
    if not exp:
        return None
    return max(0, (exp - datetime.now()).days)


def format_expires(row: dict) -> str | None:
    exp = _parse_expires(row)
    return exp.strftime("%d/%m/%Y") if exp else None
