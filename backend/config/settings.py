from pathlib import Path
import os
import json
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-your-secret-key-here'

DEBUG = True

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'channels',
    'mailer',
    'drf_yasg',
    'django_celery_results',
    'django_celery_beat',
    'django_prometheus',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.gzip.GZipMiddleware',
    'csp.middleware.CSPMiddleware',
    'mailer.middleware.auth.TokenAuthMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_prometheus.middleware.PrometheusBeforeMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'mailer',
        'USER': 'root',
        'PASSWORD': '246808642aA@',
        'HOST': 'db',
        'PORT': '3306',
        'OPTIONS': {
            'charset': 'utf8mb4',
        }
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

WHITENOISE_MAX_AGE = 31536000  # 1 year
WHITENOISE_MANIFEST_STRICT = False
WHITENOISE_USE_FINDERS = True
WHITENOISE_COMPRESS = True
WHITENOISE_MIMETYPES = {
    'application/javascript': 'text/javascript',
    'text/css': 'text/css',
}

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
]

ADMIN_MEDIA_PREFIX = '/static/admin/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} - {name} - {levelname} - {message}',
            'style': '{',
        },
        'audit': {
            'format': '{message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'mailer': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'audit': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Настройки Channels
ASGI_APPLICATION = 'config.asgi.application'
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("redis", 6379)],
            "capacity": 1500,
            "expiry": 10,
        },
    },
}

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Добавим настройки DRF и Spectacular
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.coreapi.AutoSchema',
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'mailer.throttling.CustomRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'custom': '1000/day',
        'auth': '5/min',
        'mailing': '2/min',
        'check': '10/min',
        'upload': '20/min',
    }
}

SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    },
    'USE_SESSION_AUTH': False,
    'JSON_EDITOR': True,
    'DISPLAY_OPERATION_ID': False,
    'SUPPORTED_SUBMIT_METHODS': ['get', 'post', 'put', 'delete'],
    'VALIDATOR_URL': None,
}

# Загрузка настроек из settings.json
with open(os.path.join(BASE_DIR, 'settings.json')) as f:
    MAILER_SETTINGS = json.load(f)

# Настройки для рассылки
SMTP_SETTINGS = {
    'timeout': MAILER_SETTINGS.get('timeout', 60),
    'max_attempts': MAILER_SETTINGS.get('smtphost_max_attempts', 3),
    'servers': MAILER_SETTINGS.get('servers', []),
    'random_host': MAILER_SETTINGS.get('random_smtphost', False),
}

# Настройки для проверки прокси
PROXY_SETTINGS = {
    'reverse_socks': MAILER_SETTINGS.get('reverse_socks_list', False),
    'recheck_ip': MAILER_SETTINGS.get('recheck_real_ip', True),
    'ip_apis': MAILER_SETTINGS.get('ip_apis', []),
}

# Настройки для DNS
DNS_SETTINGS = {
    'dnsbls': MAILER_SETTINGS.get('dnsbls', []),
    'skiplist': MAILER_SETTINGS.get('dnsbl_skiplist', []),
}

# Celery Configuration
CELERY_BROKER_URL = 'redis://redis:6379/0'
CELERY_RESULT_BACKEND = 'django-db'
CELERY_CACHE_BACKEND = 'django-cache'
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60

# Celery Beat Configuration
from .celerybeat_schedule import CELERYBEAT_SCHEDULE
CELERY_BEAT_SCHEDULE = {
    'cleanup-temp-files': {
        'task': 'mailer.tasks.cleanup_temp_files',
        'schedule': timedelta(hours=1),
    },
    'archive-old-logs': {
        'task': 'mailer.tasks.archive_old_logs',
        'schedule': timedelta(days=1),
    },
}

# Celery Logging
CELERYD_LOG_FILE = "/var/log/celery/worker.log"
CELERYBEAT_LOG_FILE = "/var/log/celery/beat.log"

# Sentry Configuration
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.redis import RedisIntegration

if not DEBUG:  # Включаем Sentry только в production
    sentry_sdk.init(
        dsn="https://your-dsn@sentry.io/your-project",
        integrations=[
            DjangoIntegration(),
            RedisIntegration(),
            CeleryIntegration(),
        ],
        traces_sample_rate=1.0,
        send_default_pii=True,
        environment='development',
    )

# Rate Limiting Settings
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_FAIL_OPEN = False  # Блокировать при проблемах с кэшем

# Redis Configuration
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    }
}

# Cache time to live is 15 minutes
CACHE_TTL = 60 * 15

# Cache ops configuration
CACHEOPS_REDIS = 'redis://redis:6379/3'
CACHEOPS_DEFAULTS = {
    'timeout': 60*15  # 15 minutes
}

CACHEOPS = {
    'mailer.Proxy': {'ops': 'all', 'timeout': 60*15},
    'mailer.Template': {'ops': 'all', 'timeout': 60*60},
    'mailer.Base': {'ops': 'all', 'timeout': 60*60},
    'mailer.Session': {'ops': 'all', 'timeout': 60*60*24},
    'mailer.Setting': {'ops': 'all', 'timeout': 60*60*24},
}

# WebSocket settings
WEBSOCKET_SETTINGS = {
    'ping_interval': 30,  # Интервал ping/pong в секундах
    'connection_timeout': 60,  # Таймаут подключения
    'max_connections': 1000,  # Максимальное количество подключений
    'reconnect_attempts': 3,  # Количество попыток переподключения
}

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_SECONDS = 31536000

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", "'unsafe-eval'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "https:", "data:")

# CSRF Settings
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
]

# Session Settings
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# XSS Protection
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'

# Debug Toolbar Settings
if DEBUG:
    pass

# Query Count Settings
QUERYCOUNT = {
    'THRESHOLDS': {
        'MEDIUM': 50,
        'HIGH': 200,
        'MIN_TIME_TO_LOG': 0,
        'MIN_QUERY_COUNT_TO_LOG': 50
    },
    'IGNORE_REQUEST_PATTERNS': [],
    'IGNORE_SQL_PATTERNS': []
}

# Compression Settings
COMPRESS_ENABLED = True
COMPRESS_OFFLINE = True
COMPRESS_CSS_FILTERS = ['compressor.filters.css_default.CssAbsoluteFilter']
COMPRESS_JS_FILTERS = ['compressor.filters.jsmin.JSMinFilter']

# Audit Logging Settings
AUDIT_LOGGING = {
    'ENABLED': True,
    'EXCLUDED_PATHS': ['/static/', '/media/'],
    'LOG_PATH': os.path.join(BASE_DIR, 'logs', 'audit.log'),
    'RETENTION_DAYS': 30,
}

# Cache settings
CACHE_MIDDLEWARE_SECONDS = 31536000  # 1 year for static files
CACHE_MIDDLEWARE_KEY_PREFIX = 'mailer'

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}