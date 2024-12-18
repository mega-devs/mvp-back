from django.urls import path, include
from . import views

urlpatterns = [
    # Authentication
    path('authentication/register/', views.RegisterView.as_view(), name='register'),
    path('authentication/login/', views.LoginView.as_view(), name='login'),
    
    # Sessions
    path('sessions/', views.SessionListView.as_view(), name='session-list'),
    path('sessions/<str:name>/', views.SessionDetailView.as_view(), name='session-detail'),
    
    # SMTP endpoints
    path('smtp/', views.SMTPListCreateView.as_view(), name='smtp-list'),
    path('smtp/<int:pk>/', views.SMTPDetailView.as_view(), name='smtp-detail'),
    path('smtp/<int:pk>/check/', views.SMTPCheckView.as_view(), name='smtp-check'),

    # Proxy endpoints
    path('proxy/', views.ProxyListCreateView.as_view(), name='proxy-list'),
    path('proxy/<int:pk>/', views.ProxyDetailView.as_view(), name='proxy-detail'),
    path('proxy/<int:pk>/check/', views.ProxyCheckView.as_view(), name='proxy-check'),

    # Monitoring endpoints
    path('monitoring/status/', views.SystemStatusView.as_view(), name='system-status'),
    path('monitoring/metrics/', views.MetricsView.as_view(), name='metrics'),

    # ... остальные пути ...
] 