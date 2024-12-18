from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from mailer.views import MetricsView

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # API Schema
    path('api/schema/', SpectacularAPIView.as_view(
        api_version='1.0.0',
        permission_classes=[]
    ), name='schema'),
    
    # Swagger UI
    path('api/docs/', SpectacularSwaggerView.as_view(
        url_name='schema',
        permission_classes=[]
    ), name='swagger-ui'),
    
    # API URLs
    path('api/', include('mailer.urls')),
    
    # Metrics
    path('metrics/', MetricsView.as_view(), name='metrics-root'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)