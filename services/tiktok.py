"""
services/tiktok.py — TikTok Ads API integration (placeholder)
TODO: Implement khi có TIKTOK_APP_ID + TIKTOK_APP_SECRET
"""
import json
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

import config
from extensions import logger
from models.connection import save_connection


def _http_post(url: str, data: dict, timeout: int = 10) -> dict:
    p = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=p, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def tiktok_refresh(uid: int, row: dict) -> str | None:
    if not row.get("refresh_token"):
        return None
    try:
        d = _http_post(config.TIKTOK_TOKEN_URL, {
            "app_id":        config.TIKTOK_APP_ID,
            "secret":        config.TIKTOK_APP_SECRET,
            "refresh_token": row["refresh_token"],
            "grant_type":    "refresh_token",
        }).get("data", {})
        exp = (datetime.now() + timedelta(
            seconds=d.get("access_token_expire_in", 7_776_000)
        )).isoformat()
        save_connection(
            uid, "tiktok",
            d["access_token"], d.get("refresh_token", row["refresh_token"]),
            exp, row["account_id"], row["account_name"],
        )
        return d["access_token"]
    except Exception as e:
        logger.error("TikTok token refresh failed user=%d: %s", uid, e)
        return None


def tiktok_fetch(uid: int, row: dict, days: int = 7) -> dict | None:
    """
    TODO: Implement TikTok Ads API
    Endpoint: /open_api/v1.3/report/integrated/get/
    Cần: advertiser_id, access_token
    Tham khảo: https://business-api.tiktok.com/portal/docs
    """
    logger.debug("tiktok_fetch: not implemented yet (user=%d)", uid)
    return None
