from celery import Celery
from config import get_settings

settings = get_settings()

celery_app = Celery(
    "social_fraud_detector",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["scheduler.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "poll-meta": {
            "task": "scheduler.tasks.poll_platform",
            "schedule": settings.polling_interval_meta,
            "args": ("facebook",),
        },
        "poll-instagram": {
            "task": "scheduler.tasks.poll_platform",
            "schedule": settings.polling_interval_meta,
            "args": ("instagram",),
        },
        "poll-twitter": {
            "task": "scheduler.tasks.poll_platform",
            "schedule": settings.polling_interval_twitter,
            "args": ("twitter",),
        },
        "poll-youtube": {
            "task": "scheduler.tasks.poll_platform",
            "schedule": settings.polling_interval_youtube,
            "args": ("youtube",),
        },
    },
)
