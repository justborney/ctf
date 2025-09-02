from datetime import timedelta

import billiard
from celery import Celery
from celery.concurrency.prefork import TaskPool as PreforkTaskPool

from settings import CELERY_BROKER_URL, CELERY_RESULT_BACKEND, PARSE_ALL_SOURCES_INTERVAL_SECONDS


class TaskPool(PreforkTaskPool):
    start_method = "spawn"

    def on_start(self):
        billiard.set_start_method(self.start_method, force=True)
        super().on_start()


celery_app = Celery(
    "crypto_analysis",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=["tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

celery_app.conf.worker_pool = 'celery_app.TaskPool'

celery_app.conf.beat_schedule = {
    "parse-all-sources-interval": {
        "task": "tasks.parse_all_sources",
        "schedule": timedelta(seconds=PARSE_ALL_SOURCES_INTERVAL_SECONDS),
    },
}
