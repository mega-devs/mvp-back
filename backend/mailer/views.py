from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.utils import timezone
import secrets
import json
import logging

from .models import *
from .serializers import *
from . import utils
from .services import MailerService

logger = logging.getLogger('mailer')

class LoginView(generics.CreateAPIView):
    """User login endpoint"""
    serializer_class = UserSerializer
    permission_classes = []

    def create(self, request, *args, **kwargs):
        if utils.validate(request.data, ['name', 'password']):
            user = authenticate(username=request.data['name'], 
                              password=request.data['password'])
            if user:
                token = secrets.token_hex(8)
                Token.objects.create(user=user, token=token)
                logger.info(f'User {request.data["name"]} logged in successfully')
                return Response({'token': token})
            else:
                logger.warning(f'Login failed for user {request.data["name"]}')
                return Response(
                    {'error': 'user not found or password is incorrect'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
        else:
            logger.error('Login failed due to wrong parameters')
            return Response(
                {'error': 'wrong params'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class SessionListView(generics.ListCreateAPIView):
    """List and create sessions"""
    serializer_class = SessionSerializer
    permission_classes = [IsAuthenticated]
    queryset = Session.objects.all()

    def perform_create(self, serializer):
        session = serializer.save()
        
        # Load settings from json file
        with open('settings.json') as f:
            settings = json.load(f)
        
        # Create settings for session
        for key, value in settings.items():
            Setting.objects.create(
                session=session.name,
                type=key,
                data=value if isinstance(value, int) else None
            )
            
        logger.info(f'Session {session.name} added successfully')

class SessionDetailView(generics.DestroyAPIView):
    """Delete session"""
    serializer_class = SessionSerializer
    permission_classes = [IsAuthenticated]
    queryset = Session.objects.all()
    lookup_field = 'name'

    def perform_destroy(self, instance):
        Setting.objects.filter(session=instance.name).delete()
        super().perform_destroy(instance)
        logger.info(f'Session {instance.name} deleted successfully')

class MaterialListView(generics.ListCreateAPIView):
    """List and create materials"""
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        material_type = self.kwargs.get('type')
        serializer_map = {
            'smtps': SMTPSerializer,
            'proxies': ProxySerializer,
            'bases': BaseEmailSerializer,
            'domains': DomainSerializer,
            'templates': TemplateSerializer,
            'imaps': IMAPSerializer,
        }
        return serializer_map.get(material_type)

    def get_queryset(self):
        material_type = self.kwargs.get('type')
        session = self.kwargs.get('session')
        model_map = {
            'smtps': SMTP,
            'proxies': Proxy,
            'bases': Base,
            'domains': Domain,
            'templates': Template,
            'imaps': IMAP,
        }
        model = model_map.get(material_type)
        if model:
            return model.objects.filter(session=session)
        return None

    def create(self, request, *args, **kwargs):
        material_type = kwargs.get('type')
        if not utils.validate(request.data, ['content', 'session']):
            return Response(
                {'error': 'missing required fields'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            result = MailerService.process_materials(
                request.data['session'],
                material_type,
                request.data['content']
            )
            return Response(result)
        except Exception as e:
            logger.error(f'Error processing material: {str(e)}')
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class TemplateView(generics.CreateAPIView, generics.UpdateAPIView):
    """Create and update templates"""
    serializer_class = TemplateSerializer
    permission_classes = [IsAuthenticated]
    queryset = Template.objects.all()

    def perform_create(self, serializer):
        template = serializer.save()
        logger.info(f'Template {template.id} created successfully')

    def perform_update(self, serializer):
        template = serializer.save()
        logger.info(f'Template {template.id} updated successfully')

class LogListView(generics.ListCreateAPIView):
    """List and create logs"""
    serializer_class = LogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        session = self.kwargs.get('session')
        log_type = self.kwargs.get('type')
        query = {'session': session}
        if log_type:
            query['type'] = log_type
        return Log.objects.filter(**query).order_by('-created_at')[:100]

class CheckView(generics.CreateAPIView):
    """Check various components (SMTP, IMAP, proxy, domain)"""
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        check_type = kwargs.get('type')
        if not utils.validate(request.data, ['session', 'ids']):
            return Response(
                {'error': 'missing required fields'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            check_map = {
                'smtp': MailerService.check_smtps,
                'imap': MailerService.check_imaps,
                'proxy': MailerService.check_proxies,
                'domain': MailerService.check_domains,
            }
            
            checker = check_map.get(check_type)
            if not checker:
                return Response(
                    {'error': f'Invalid check type: {check_type}'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            result = checker(request.data['session'], request.data['ids'])
            return Response(result)
            
        except Exception as e:
            logger.error(f'Error checking {check_type}: {str(e)}')
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class MailingView(generics.CreateAPIView):
    """Start mailing campaign"""
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        if not utils.validate(request.data, ['session', 'sending_limit', 'threads_number']):
            return Response(
                {'error': 'missing required fields'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            result = MailerService.start_mass_mailing(
                request.data['session'],
                request.data
            )
            if result:
                return Response({'status': 'success'})
            return Response(
                {'error': 'mailing failed'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            logger.error(f'Error in mailing: {str(e)}')
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

