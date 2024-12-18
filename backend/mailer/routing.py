from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(
        r'ws/session/(?P<session>\w+)/$',
        consumers.BaseWebSocketConsumer.as_asgi()
    ),
] 