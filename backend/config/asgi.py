import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from mailer.middleware.websocket import WebSocketAuthMiddleware
from mailer.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        WebSocketAuthMiddleware(
            URLRouter(
                websocket_urlpatterns
            )
        )
    ),
}) 