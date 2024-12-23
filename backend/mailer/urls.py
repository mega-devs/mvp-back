from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = 'mailer'

urlpatterns = [
    # Authentication endpoints
    path('authentication/register/', views.RegisterView.as_view(), name='register'),
    path('authentication/login/', views.LoginView.as_view(), name='login'),
    path('authentication/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # SMTP endpoints
    path('smtp/', views.SMTPListView.as_view(), name='smtp-list'),
    path('smtp/create/', views.SMTPCreateView.as_view(), name='smtp-create'),
    path('smtp/<int:pk>/', views.SMTPRetrieveView.as_view(), name='smtp-detail'),
    path('smtp/<int:pk>/update/', views.SMTPUpdateView.as_view(), name='smtp-update'),
    path('smtp/<int:pk>/delete/', views.SMTPDeleteView.as_view(), name='smtp-delete'),
    path('smtp/<int:pk>/check/', views.SMTPCheckView.as_view(), name='smtp-check'),

    # Proxy endpoints
    path('proxy/', views.ProxyListCreateView.as_view(), name='proxy-list'),
    path('proxy/<int:pk>/', views.ProxyDetailView.as_view(), name='proxy-detail'),
    path('proxy/<int:pk>/check/', views.ProxyCheckView.as_view(), name='proxy-check'),

    # Material endpoints
    path('materials/<str:type>/', views.MaterialListView.as_view(), name='material-list'),
    path('materials/check/', views.MaterialCheckView.as_view(), name='material-check'),

    # Log endpoints
    path('logs/<str:session>/', views.LogView.as_view(), name='logs'),

    # Mailing endpoints
    path('mailing/start/', views.MailingView.as_view(), name='mailing-start'),
    path('mailing/mass/', views.MassMailingView.as_view(), name='mass-mailing'),

    # Monitoring endpoints
    path('monitoring/status/', views.SystemStatusView.as_view(), name='system-status'),
    path('monitoring/metrics/', views.MetricsView.as_view(), name='metrics'),
] 