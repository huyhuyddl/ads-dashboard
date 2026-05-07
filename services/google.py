"""
services/google.py — Google Ads API integration (placeholder)
TODO: Implement khi có GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET
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


def google_refresh(uid: int, row: dict) -> str | None:
    if not row.get("refresh_token"):
        return None
    try:
        d = _http_post(config.GOOGLE_TOKEN_URL, {
            "client_id":     config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "refresh_token": row["refresh_token"],
            "grant_type":    "refresh_token",
        })
        exp = (datetime.now() + timedelta(seconds=d.get("expires_in", 3600))).isoformat()
        save_connection(
            uid, "google", d["access_token"], row["refresh_token"],
            exp, row["account_id"], row["account_name"],
        )
        return d["access_token"]
    except Exception as e:
        logger.error("Google token refresh failed user=%d: %s", uid, e)
        return None


def google_fetch(uid: int, row: dict, days: int = 7) -> dict | None:
    """
    TODO: Implement Google Ads API
    Cần: google-ads-python SDK, customer_id, GoogleAdsService query
    Tham khảo: https://developers.google.com/google-ads/api/docs/get-started
    """
    logger.debug("google_fetch: not implemented yet (user=%d)", uid)
    return None
