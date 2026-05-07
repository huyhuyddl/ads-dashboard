"""
services/facebook.py — Facebook Ads API integration
Hiện tại: OAuth flow hoàn chỉnh, fetch data thật khi có token.
"""
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta

import config
from extensions import logger
from models.connection import save_connection, deactivate_connection, token_expired, token_expiring
from models.activity import log_activity


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _http_post(url: str, data: dict, timeout: int = 10) -> dict:
    p = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=p, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ── Token management ───────────────────────────────────────────────────────

def fb_to_long_lived(short_token: str) -> tuple[str, str]:
    """Đổi short-lived token → long-lived (~60 ngày). Trả về (token, expires_at ISO)."""
    params = urllib.parse.urlencode({
        "grant_type":        "fb_exchange_token",
        "client_id":         config.FB_APP_ID,
        "client_secret":     config.FB_APP_SECRET,
        "fb_exchange_token": short_token,
    })
    d   = _http_get(f"{config.FB_TOKEN_URL}?{params}")
    exp = (datetime.now() + timedelta(seconds=int(d.get("expires_in", 5_184_000)))).isoformat()
    return d["access_token"], exp


def fb_refresh(uid: int, row: dict) -> str | None:
    """Thử làm mới token. Trả về token mới hoặc None nếu thất bại."""
    try:
        new_tok, new_exp = fb_to_long_lived(row["access_token"])
        save_connection(
            uid, "facebook", new_tok, None, new_exp,
            row["account_id"], row["account_name"], row.get("scopes", "[]"),
        )
        log_activity(uid, "FB_TOKEN_REFRESH", "Auto-refresh OK")
        logger.info("FB token refreshed for user=%d", uid)
        return new_tok
    except Exception as e:
        logger.error("FB token refresh failed user=%d: %s", uid, e)
        deactivate_connection(uid, "facebook")
        log_activity(uid, "FB_TOKEN_EXPIRED", "Token hết hạn, cần kết nối lại")
        return None


def get_valid_fb_token(uid: int, row: dict) -> str | None:
    if token_expired(row):
        return fb_refresh(uid, row)
    if token_expiring(row):
        try:
            fb_refresh(uid, row)
        except Exception:
            pass
    return row["access_token"]


# ── Data fetch ─────────────────────────────────────────────────────────────

def fb_fetch(uid: int, row: dict, days: int = 7) -> dict | None:
    """
    Fetch dữ liệu thực từ Facebook Ads API.
    Trả về dict chuẩn hoặc None nếu thất bại.
    """
    token = get_valid_fb_token(uid, row)
    if not token or not row.get("account_id"):
        return None

    date_end   = datetime.now().strftime("%Y-%m-%d")
    date_start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    url = (
        f"{config.FB_API}/{row['account_id']}/insights"
        f"?fields=spend,impressions,clicks,actions,action_values"
        f"&time_range={{\"since\":\"{date_start}\",\"until\":\"{date_end}\"}}"
        f"&time_increment=1&access_token={token}"
    )
    try:
        res = _http_get(url)
        if "error" in res:
            code = res["error"].get("code")
            logger.warning("FB API error code=%s user=%d", code, uid)
            if code in (190, 102):
                fb_refresh(uid, row)
            return None

        rows = res.get("data", [])
        if not rows:
            logger.info("FB API returned empty data for user=%d", uid)
            return None

        labels, spend_s = [], []
        ts = tr = cl = imp = 0

        for r in rows:
            labels.append(r.get("date_start", "")[-5:].replace("-", "/"))
            sp = float(r.get("spend", 0)) * config.USD_TO_VND
            spend_s.append(round(sp / 1_000_000, 2))
            ts  += sp
            cl  += int(r.get("clicks", 0))
            imp += int(r.get("impressions", 0))
            for av in r.get("action_values", []):
                if av["action_type"] == "purchase":
                    tr += float(av["value"]) * config.USD_TO_VND

        roas = round(tr / ts, 2) if ts else 0
        roi  = round((tr - ts) / ts * 100, 1) if ts else 0

        return {
            "platform":      "facebook",
            "source":        "api",
            "labels":        labels,
            "spend_series":  spend_s,
            "total_spend":   round(ts),
            "total_revenue": round(tr),
            "roas":          roas,
            "roi":           roi,
            "cpa":           round(ts / cl) if cl else 0,
            "clicks":        cl,
            "impressions":   imp,
            "ctr":           round(cl / max(imp, 1) * 100, 2),
        }
    except Exception as e:
        logger.error("FB fetch error user=%d: %s", uid, e)
        return None
