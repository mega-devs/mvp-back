from celery.schedules import crontab

CELERYBEAT_SCHEDULE = {
    'check-smtp-daily': {
        'task': 'mailer.tasks.check_smtp_task',
        'schedule': crontab(hour=0, minute=0),  # Каждый день в полночь
    },
    'check-proxy-hourly': {
        'task': 'mailer.tasks.check_proxy_task',
        'schedule': crontab(minute=0),  # Каждый час
    },
} 