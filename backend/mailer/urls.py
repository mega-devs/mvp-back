from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Authentication
    path('authentication/register/', views.RegisterView.as_view(), name='register'),
    path('authentication/login/', views.LoginView.as_view(), name='login'),
    path('authentication/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # SMTP endpoints
    path('smtp/', views.SMTPListView.as_view()),
    path('smtp/create/', views.SMTPCreateView.as_view()),
    path('smtp/<int:pk>/', views.SMTPRetrieveView.as_view()),
    path('smtp/<int:pk>/update/', views.SMTPUpdateView.as_view()),
    path('smtp/<int:pk>/delete/', views.SMTPDeleteView.as_view()),
    path('smtp/<int:pk>/check/', views.SMTPCheckView.as_view(), name='smtp-check'),

    # Proxy endpoints
    path('proxy/', views.ProxyListCreateView.as_view(), name='proxy-list'),
    path('proxy/<int:pk>/', views.ProxyDetailView.as_view(), name='proxy-detail'),
    path('proxy/<int:pk>/check/', views.ProxyCheckView.as_view(), name='proxy-check'),

    # Monitoring endpoints
    path('monitoring/status/', views.SystemStatusView.as_view(), name='system-status'),
    path('monitoring/metrics/', views.MetricsView.as_view(), name='metrics'),

    # Sessions (если нужны)
    path('sessions/', views.SessionListView.as_view(), name='session-list'),
    path('sessions/<str:name>/', views.SessionDetailView.as_view(), name='session-detail'),
] 