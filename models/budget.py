"""
models/budget.py — CRUD cho bảng budgets
"""
from extensions import get_db
import config


def get_budgets(user_id: int) -> dict:
    """Trả về {platform: monthly_limit} cho user."""
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute(
                "SELECT platform, monthly_limit FROM budgets WHERE user_id=%s",
                (user_id,),
            )
            rows = c.fetchall()
        return {r["platform"]: r["monthly_limit"] for r in rows}
    finally:
        conn.close()


def check_budget_alerts(budgets: dict, channel_stats: dict) -> list[dict]:
    """
    So sánh spend thực với budget.
    Trả về list các alert: [{platform, percent, status}]
    status: "danger" (>= BUDGET_DANGER_PCT) | "warn" (>= BUDGET_WARN_PCT)
    """
    alerts = []
    for platform, limit in budgets.items():
        if not limit:
            continue
        spend = channel_stats.get(platform, {}).get("spend", 0)
        pct   = round(spend / limit * 100, 1)
        if pct >= config.BUDGET_DANGER_PCT:
            alerts.append({"platform": platform, "percent": pct, "status": "danger"})
        elif pct >= config.BUDGET_WARN_PCT:
            alerts.append({"platform": platform, "percent": pct, "status": "warn"})
    return alerts
