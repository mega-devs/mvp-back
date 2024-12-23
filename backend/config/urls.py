from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from mailer.views import (
    MetricsView, 
    SMTPListView,
    SMTPCreateView,
    SMTPRetrieveView,
    SMTPUpdateView,
    SMTPDeleteView,
    SMTPCheckView,
    ProxyListCreateView,
    ProxyDetailView,
    ProxyCheckView,
    SystemStatusView
)

schema_view = get_schema_view(
    openapi.Info(
        title="Mailer API",
        default_version='v1',
        description="API для управления SMTP серверами и рассылками",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    patterns=[
        path('api/', include('mailer.urls')),
    ],
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('mailer.urls')),
    
    # Swagger URLs
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # Metrics
    path('metrics/', MetricsView.as_view(), name='metrics'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)