from prometheus_client import Counter, Histogram
import time

# Метрики для SMTP
smtp_check_total = Counter(
    'smtp_check_total',
    'Total number of SMTP checks',
    ['status']  # success/failure
)

smtp_check_duration = Histogram(
    'smtp_check_duration_seconds',
    'Time spent checking SMTP servers',
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)

# Метрики для прокси
proxy_check_total = Counter(
    'proxy_check_total',
    'Total number of proxy checks',
    ['status']  # success/failure
)

proxy_check_duration = Histogram(
    'proxy_check_duration_seconds',
    'Time spent checking proxies',
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)

# Метрики для Celery задач
celery_tasks_total = Counter(
    'celery_tasks_total',
    'Total number of Celery tasks',
    ['task_name', 'status']  # task name and success/failure
)

celery_task_duration = Histogram(
    'celery_task_duration_seconds',
    'Time spent executing Celery tasks',
    ['task_name'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
)

# Метрики для рассылок
mailing_total = Counter(
    'mailing_total',
    'Total number of emails sent',
    ['status']  # success/failure/bounced
)

mailing_duration = Histogram(
    'mailing_duration_seconds',
    'Time spent sending emails',
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0]
)

# Утилиты для измерения времени
class timer:
    def __init__(self, metric):
        self.metric = metric
        
    def __enter__(self):
        self.start = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start
        self.metric.observe(duration) 