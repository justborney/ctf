import os

APP_TITLE = os.getenv("APP_TITLE", "Crypto Market Analysis")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

DATA_DIR = os.getenv("DATA_DIR", "data")
UPLOADS_DIR = os.getenv("UPLOADS_DIR", "uploads")
RESULTS_DIR = os.getenv("RESULTS_DIR", "results")

SOURCES_FILE = os.getenv("SOURCES_FILE", f"{DATA_DIR}/sources.json")

PEACH_COIN_SERVICE_URL = os.getenv("PEACH_COIN_SERVICE_URL", "http://peach-coin:8001")

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

PARSE_ALL_SOURCES_INTERVAL_SECONDS = int(os.getenv("PARSE_ALL_SOURCES_INTERVAL_SECONDS", "30"))
