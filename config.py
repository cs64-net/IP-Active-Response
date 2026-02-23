import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "soc_ip_blocker.db"))
    DEFAULT_BLOCK_METHOD = "floating_rule"
    MONITOR_INTERVAL = 120  # seconds
    DEFAULT_ADMIN_USER = "admin"
    DEFAULT_ADMIN_PASSWORD = "admin"
