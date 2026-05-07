"""
extensions.py — Khởi tạo các shared extension: DB pool, logger
"""
import logging
import sys
import pymysql
import pymysql.cursors
from dbutils.pooled_db import PooledDB
import config

# ── Logger ─────────────────────────────────────────────────────────────────
def setup_logger() -> logging.Logger:
    logger = logging.getLogger("ads_dashboard")
    if logger.handlers:
        return logger  # Đã khởi tạo rồi

    logger.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    import os
    os.makedirs("instance", exist_ok=True)

    logger = logging.getLogger("app")
    fh = logging.FileHandler("instance/app.log", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


logger = setup_logger()


# ── MySQL Connection Pool ──────────────────────────────────────────────────
_pool: PooledDB | None = None


def get_pool() -> PooledDB:
    global _pool
    if _pool is None:
        _pool = PooledDB(
            creator=pymysql,
            maxconnections=config.MYSQL_POOL_SIZE,
            mincached=2,
            maxcached=5,
            blocking=True,
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USER,
            password=config.MYSQL_PASSWORD,
            database=config.MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor,
            charset="utf8mb4",
            autocommit=False,
        )
        logger.info("MySQL connection pool initialized (max=%d)", config.MYSQL_POOL_SIZE)
    return _pool


def get_db():
    """Lấy connection từ pool. Dùng với context manager hoặc đóng thủ công."""
    return get_pool().connection()
