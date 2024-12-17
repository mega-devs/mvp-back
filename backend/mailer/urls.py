from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('login', views.LoginView.as_view(), name='login'),
    
    # Sessions
    path('sessions', views.SessionListView.as_view(), name='session-list'),
    path('sessions/<str:name>', views.SessionDetailView.as_view(), name='session-detail'),
    
    # Materials
    path('materials/<str:type>/<str:session>', 
         views.MaterialListView.as_view(), name='material-list'),
    
    # Templates
    path('templates', views.TemplateView.as_view(), name='template-create'),
    path('templates/<int:pk>', views.TemplateView.as_view(), name='template-update'),
    
    # Logs
    path('logs/<str:session>', views.LogListView.as_view(), name='log-list'),
    path('logs/<str:session>/<str:type>', 
         views.LogListView.as_view(), name='log-list-filtered'),
    
    # Checks
    path('check/<str:type>', views.CheckView.as_view(), name='check'),
    
    # Mailing
    path('mailing', views.MailingView.as_view(), name='mailing'),
] 