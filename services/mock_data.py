"""
services/mock_data.py — Sinh dữ liệu giả cho dashboard khi chưa có API thật
"""
import random
from datetime import datetime, timedelta
import config


def mock_platform(uid: int, platform: str, days: int = 7) -> dict:
    cfg = config.MOCK_CFG[platform]
    random.seed(uid * 31 + list(config.MOCK_CFG).index(platform))

    labels, spend_s = [], []
    for i in range(days):
        d = datetime.now() - timedelta(days=days - 1 - i)
        labels.append(d.strftime("%d/%m"))
        spend_s.append(round(cfg["base"] * random.uniform(0.7, 1.3) / 1_000_000, 2))

    ts  = sum(spend_s) * 1_000_000
    tr  = ts * random.uniform(2.8, 4.5)
    cl  = random.randint(1_200, 8_000)
    imp = random.randint(80_000, 500_000)

    return {
        "platform":     platform,
        "source":       "mock",
        "labels":       labels,
        "spend_series": spend_s,
        "total_spend":  round(ts),
        "total_revenue": round(tr),
        "roas":         round(tr / ts, 2),
        "roi":          round((tr - ts) / ts * 100, 1),
        "cpa":          round(ts / cl),
        "clicks":       cl,
        "impressions":  imp,
        "ctr":          round(cl / imp * 100, 2),
    }
