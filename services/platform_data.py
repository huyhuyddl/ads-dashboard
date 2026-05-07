"""
services/platform_data.py — Tổng hợp dữ liệu từ các platform
Điều phối giữa API thật và mock data.
"""
from extensions import logger
from models.connection import get_connections, mark_last_synced, token_expired
from models.budget import get_budgets, check_budget_alerts
from services.mock_data import mock_platform
from services.facebook import fb_fetch
from services.google import google_fetch
from services.tiktok import tiktok_fetch
import config

# Map platform → fetch function
_FETCHERS = {
    "facebook": fb_fetch,
    "google":   google_fetch,
    "tiktok":   tiktok_fetch,
}


def get_platform_data(uid: int, platform: str, days: int = 7, force_mock: bool = False) -> dict:
    """
    Lấy data cho 1 platform.
    Ưu tiên: API thật → mock (nếu API lỗi hoặc force_mock=True).
    """
    connections = get_connections(uid)
    row = connections.get(platform)

    if force_mock or not row:
        data = mock_platform(uid, platform, days)
        data["is_mock"]      = True
        data["is_connected"] = bool(row)
        data["needs_reauth"] = False
        return data

    real = _FETCHERS[platform](uid, row, days)
    if real:
        real["is_mock"]      = False
        real["is_connected"] = True
        real["needs_reauth"] = False
        mark_last_synced(uid, platform)
        logger.info("Fetched real data: user=%d platform=%s days=%d", uid, platform, days)
        return real

    # Fallback về mock
    logger.warning("Falling back to mock: user=%d platform=%s", uid, platform)
    data = mock_platform(uid, platform, days)
    data["is_mock"]      = True
    data["is_connected"] = True
    data["needs_reauth"] = token_expired(row)
    return data


def get_all_platforms(uid: int, days: int = 7, force_mock: bool = False) -> dict:
    """
    Lấy data tổng hợp cho tất cả platform.
    Trả về format chuẩn cho /api/dashboard-data.
    """
    platforms = {p: get_platform_data(uid, p, days, force_mock) for p in config.PLATFORMS}

    ts     = sum(p["total_spend"]   for p in platforms.values())
    tr     = sum(p["total_revenue"] for p in platforms.values())
    cl     = sum(p["clicks"]        for p in platforms.values())
    labels = platforms["facebook"]["labels"]

    merged = [
        round(sum(platforms[p]["spend_series"][i] for p in config.PLATFORMS), 2)
        for i in range(len(labels))
    ]

    spend_series = {
        p: platforms[p]["spend_series"] for p in config.PLATFORMS
    }
    spend_series["merged"] = merged

    channel_stats = {
        p: {
            "spend":        platforms[p]["total_spend"],
            "revenue":      platforms[p]["total_revenue"],
            "roas":         platforms[p]["roas"],
            "roi":          platforms[p]["roi"],
            "cpa":          platforms[p]["cpa"],
            "clicks":       platforms[p]["clicks"],
            "impressions":  platforms[p]["impressions"],
            "ctr":          platforms[p]["ctr"],
            "is_mock":      platforms[p]["is_mock"],
            "is_connected": platforms[p]["is_connected"],
        }
        for p in config.PLATFORMS
    }

    connected = get_connections(uid)

    return {
        "source":          "mixed" if any(not p["is_mock"] for p in platforms.values()) else "mock",
        "labels":          labels,
        "spend_series":    spend_series,
        "total_spend":     round(ts),
        "total_revenue":   round(tr),
        "roas":            round(tr / ts, 2) if ts else 0,
        "roi":             round((tr - ts) / ts * 100, 1) if ts else 0,
        "cpa":             round(ts / cl) if cl else 0,
        "channel_stats":   channel_stats,
        "platforms":       platforms,
        "connected_count": len(connected),
    }


def build_dashboard_response(uid: int, platform: str, days: int, force_mock: bool) -> dict:
    """
    Xây dựng response hoàn chỉnh cho /api/dashboard-data.
    Bao gồm: data + budgets + budget_alerts + no_ads_data flag.
    """
    connections = get_connections(uid)
    budgets     = get_budgets(uid)

    if platform == "all":
        data = get_all_platforms(uid, days, force_mock)
    else:
        pd = get_platform_data(uid, platform, days, force_mock)
        data = {
            "source":        "mock" if pd["is_mock"] else "api",
            "labels":        pd["labels"],
            "spend_series":  {platform: pd["spend_series"]},
            "total_spend":   pd["total_spend"],
            "total_revenue": pd["total_revenue"],
            "roas":          pd["roas"],
            "roi":           pd["roi"],
            "cpa":           pd["cpa"],
            "channel_stats": {
                platform: {
                    "spend":        pd["total_spend"],
                    "revenue":      pd["total_revenue"],
                    "roas":         pd["roas"],
                    "roi":          pd["roi"],
                    "cpa":          pd["cpa"],
                    "clicks":       pd["clicks"],
                    "impressions":  pd["impressions"],
                    "ctr":          pd["ctr"],
                    "is_mock":      pd["is_mock"],
                    "is_connected": pd["is_connected"],
                }
            },
            "connected_count": len(connections),
        }

    data["budgets"]        = budgets
    data["no_ads_data"]    = len(connections) == 0
    data["budget_alerts"]  = check_budget_alerts(budgets, data.get("channel_stats", {}))

    return data
