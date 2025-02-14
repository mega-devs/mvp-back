from rest_framework import generics, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.utils import timezone
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import HttpResponse, Http404
from celery.result import AsyncResult
import json
import logging
import os
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache

from .models import *
from .serializers import (
    SessionSerializer, LoginSerializer, RegisterSerializer,
    SettingSerializer, SMTPSerializer, ProxySerializer, 
    BaseEmailSerializer, DomainSerializer, TemplateSerializer, 
    IMAPSerializer, MaterialSerializer, LogSerializer, 
    IPBlacklistSerializer, MailingRequestSerializer, 
    MailingResponseSerializer, MaterialCheckSerializer, 
    MassMailingRequestSerializer, LogClearRequestSerializer, 
    FileUploadSerializer
)
from . import utils
from .services.mailer_service import MailerService
from .services.smtp_service import SMTPService
from .services.proxy_service import ProxyService
from .services.file_service import FileService
from .services.export_service import ExportService
from .tasks import check_smtp_task, check_proxy_task, send_mass_mail_task
from .throttling import AuthRateThrottle, MailingRateThrottle, CheckRateThrottle, UploadRateThrottle
from .utils.cache_utils import cache_result, invalidate_cache
from .utils.security import SecurityUtils

logger = logging.getLogger('mailer')


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer
    permission_classes = []

    @swagger_auto_schema(
        tags=['authentication'],
        summary='Login to system',
        description='Authenticate user and get JWT tokens',
        responses={200: LoginSerializer}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            })
        return Response(
            {'error': 'Invalid credentials'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    

class RegisterView(generics.CreateAPIView):
    """User registration endpoint"""
    serializer_class = RegisterSerializer
    permission_classes = []
    throttle_classes = [AuthRateThrottle]

    @swagger_auto_schema(
        tags=['authentication'],
        operation_id='auth_register',
        request_body=RegisterSerializer,
        responses={
            201: LoginSerializer,
            400: 'Validation error'
        },
        operation_description='Create new user in system',
        operation_summary='User registration',
        request_body_required=True,
        security=[],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class SessionListView(generics.ListCreateAPIView):
    """List and create sessions"""
    serializer_class = SessionSerializer
    permission_classes = [IsAuthenticated]
    queryset = Session.objects.prefetch_related(
        'settings',
        'smtp_set',
        'proxy_set',
        'base_set'
    )

    @swagger_auto_schema(
        tags=['sessions'],
        description='Get list of sessions',
        responses={200: SessionSerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        tags=['sessions'],
        description='Create new session',
        request_body=SessionSerializer,
        responses={201: SessionSerializer},
    )
    def create(self, request, *args, **kwargs):
        session = self.save(serializer)
        
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

    @swagger_auto_schema(
        tags=['sessions'],
        description='Delete session',
        responses={204: SessionSerializer}
    )
    def perform_destroy(self, instance):
        Setting.objects.filter(session=instance.name).delete()
        super().perform_destroy(instance)
        logger.info(f'Session {instance.name} deleted successfully')
        

class MaterialListView(generics.ListCreateAPIView):
    """List and create materials"""
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        tags=['materials'],
        summary='List of materials',
        description='Get list of materials',
        manual_parameters=[
            openapi.Parameter(
                'type',
                openapi.IN_PATH,
                description='Material type',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: MaterialSerializer(many=True)
        }
    )
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
            queryset = model.objects.filter(session=session)
            if model == SMTP:
                queryset = queryset.select_related('proxy')
            return queryset.prefetch_related('logs')
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

    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)


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

    @swagger_auto_schema(
        responses={
            200: openapi.Response("Success"),
            400: openapi.Response("Bad Request"),
            500: openapi.Response("Internal Server Error")
        }
    )
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


class MailingView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MailingRequestSerializer
    throttle_classes = [MailingRateThrottle]

    @swagger_auto_schema(
        tags=['mailing'],
        summary='Start mailing',
        description='Start the mailing process',
        request_body=MailingRequestSerializer,
        responses={
            200: MailingResponseSerializer,
        }
    )
    def post(self, request):
        # Validate headers
        headers = SecurityUtils.validate_headers(request.headers)
        
        try:
            # Sanitize HTML in message
            if 'message' in request.data:
                request.data['message'] = SecurityUtils.sanitize_html(request.data['message'])
            
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                serializer.validated_data['socket_id'],
                {
                    'type': 'mailing',
                    **serializer.validated_data
                }
            )

            return Response({
                'status': 'success',
                'message': 'mailing started'
            })

        except Exception as e:
            logger.error(f'Error processing mailing: {str(e)}')
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MaterialCheckView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MaterialCheckSerializer
    throttle_classes = [CheckRateThrottle]

    @swagger_auto_schema(
        tags=['materials'],
        summary='Check materials',
        description='Start checking SMTP, proxy or other materials',
        request_body=MaterialCheckSerializer,
        responses={
            200: MailingResponseSerializer,
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        material_type = serializer.validated_data['type']
        session = serializer.validated_data['session']
        
        if material_type == 'smtp':
            smtps = SMTP.objects.filter(session=session)
            for smtp in smtps:
                # Async check via Celery
                task = check_smtp_task.delay(smtp.id)
        
        elif material_type == 'proxy':
            proxies = Proxy.objects.filter(session=session)
            for proxy in proxies:
                # Async check via Celery
                task = check_proxy_task.delay(proxy.id)

        return Response({'status': 'check started'})


class LogView(APIView):
    """Log management"""
    permission_classes = [IsAuthenticated]
    serializer_class = LogSerializer
    clear_serializer_class = LogClearRequestSerializer

    @swagger_auto_schema(
        tags=['logs'],
        summary='Get logs',
        description='Get session logs',
        manual_parameters=[
            openapi.Parameter(
                'session',
                openapi.IN_PATH,
                description='Session ID',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: LogSerializer(many=True),
        }
    )
    def get(self, request, session):
        logs = Log.objects.filter(session=session).order_by('-created_at')
        serializer = self.serializer_class(logs, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['logs'],
        summary='Clear logs',
        description='Clear logs for session',
        request_body=LogClearRequestSerializer,
        responses={
            200: MailingResponseSerializer,
        }
    )
    def delete(self, request, session):
        serializer = self.clear_serializer_class(data={'session': session})
        serializer.is_valid(raise_exception=True)
        Log.objects.filter(session=session).delete()
        return Response({'status': 'success'})


class MassMailingView(APIView):
    """Mass mailing management"""
    permission_classes = [IsAuthenticated]
    serializer_class = MassMailingRequestSerializer

    @swagger_auto_schema(
        tags=['mailing'],
        summary='Start mass mailing',
        description='Start mass mailing process',
        request_body=MassMailingRequestSerializer,
        responses={
            200: MailingResponseSerializer,
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            serializer.validated_data['socket_id'],
            {
                'type': 'mass_mailing',
                **serializer.validated_data
            }
        )

        return Response({
            'status': 'success',
            'message': 'mass mailing started'
        })
    

class SettingsView(APIView):
    """Settings management"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['settings'],
        summary='Get settings',
        description='Get settings for session',
        manual_parameters=[
            openapi.Parameter(
                'session',
                openapi.IN_PATH,
                description='Session name',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Session settings",
                schema=SettingSerializer(many=True)
            ),
        }
    )
    def get(self, request, session):
        settings = Setting.objects.filter(session=session)
        serializer = SettingSerializer(settings, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['settings'],
        summary='Update settings',
        description='Update settings for session',
        request_body=SettingSerializer,
        responses={
            200: SettingSerializer,
        }
    )
    def put(self, request, session):
        setting = Setting.objects.get(
            session=session,
            type=request.data.get('type')
        )
        serializer = SettingSerializer(setting, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ServerTimeView(APIView):
    """Get server time"""
    permission_classes = []

    @swagger_auto_schema(
        tags=['system'],
        summary='Server time',
        description='Get current server time',
        responses={
            200: openapi.Response(
                description="Server time",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'server_time': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            format='date-time'
                        )
                    }
                )
            )
        }    )
    def get(self, request):
        from django.utils import timezone
        return Response({'server_time': timezone.now().isoformat()})


class SystemStatusView(APIView):
    """API endpoint for monitoring system status"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['monitoring'],
        summary='System status',
        description='Get current system status',
        responses={
            200: openapi.Response(
                description="System status",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'components': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'database': openapi.Schema(type=openapi.TYPE_STRING),
                                'redis': openapi.Schema(type=openapi.TYPE_STRING),
                                'celery': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            503: openapi.Response(
                description="Error response",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }    )
    def get(self, request):
        status_info = {
            'status': 'healthy',
            'components': {
                'database': 'connected',
                'redis': 'connected',
                'celery': 'running'
            }
        }
        return Response(status_info)


class FileUploadView(APIView):
    """File upload for materials"""
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    @swagger_auto_schema(
        tags=['files'],
        summary='Upload file',
        description='Upload file with materials (bases, SMTP, proxy)',
        manual_parameters=[
            openapi.Parameter(
                'file',
                openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                required=True,
                description='File to upload'
            ),
            openapi.Parameter(
                'session',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                required=True,
                description='Session ID'
            ),
            openapi.Parameter(
                'type',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                required=True,
                enum=['base', 'smtp', 'proxy'],
                description='Material type'
            )
        ],
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ),
            400: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        }
    )
    def post(self, request):
        file_obj = request.FILES.get('file')
        session = request.POST.get('session')
        
        try:
            # File validation
            SecurityUtils.validate_file_upload(file_obj)
            
            # Save to temporary file
            content = file_obj.read().decode('utf-8')
            temp_path = FileService.save_temp_file(content)
            
            processor = FileService.get_processor(request.POST.get('type'))
            result = processor(content, session)
            
            # Remove temporary file
            os.remove(temp_path)
            
            return Response(result)
            
        except Exception as e:
            logger.error(f"Error processing file: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class ExportView(APIView):
    """Export data"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['export'],
        summary='Export data',
        description='Export data to CSV format',
        manual_parameters=[
            openapi.Parameter(
                'type',
                openapi.IN_PATH,
                description='Data type (bases/smtp/proxy/logs)',
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'session',
                openapi.IN_PATH,
                description='Session name',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='CSV file',
                schema=openapi.Schema(
                    type=openapi.TYPE_STRING,
                    format='binary'
                )
            ),
        }
    )
    def get(self, request, type, session):
        try:
            export_map = {
                'bases': ExportService.export_bases,
                'smtp': ExportService.export_smtp,
                'proxy': ExportService.export_proxy,
                'logs': ExportService.export_logs,
            }
            
            exporter = export_map.get(type)
            if not exporter:
                return Response(
                    {'error': f'Invalid export type: {type}'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            content = exporter(session)
            response = HttpResponse(content, content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="{type}_{session}.csv"'
            return response

        except Exception as e:
            logger.error(f'Error exporting data: {str(e)}')
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class IPBlacklistViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing IP blacklist
    """
    queryset = IPBlacklist.objects.all()
    serializer_class = IPBlacklistSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['security'],
        summary='IP blacklist',
        description='Manage blocked IP addresses',
        responses={
            200: IPBlacklistSerializer(many=True),
            401: openapi.Response(
                description='Unauthorized',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def list(self, request):
        return super().list(request)

    @swagger_auto_schema(
        tags=['security'],
        summary='Add IP to blacklist',
        request_body=IPBlacklistSerializer,
        responses={
            201: IPBlacklistSerializer,
            400: openapi.Response(
                description='Invalid data',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def create(self, request):
        return super().create(request)


class SMTPCheckView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [CheckRateThrottle]

    @swagger_auto_schema(
        tags=['smtp'],
        summary='Check SMTP',
        description='Check SMTP server connection and credentials',
        responses={
            200: openapi.Response(
                description='Task started successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: openapi.Response(
                description='Not found',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            500: openapi.Response(
                description='Internal server error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }    )
    @cache_result('smtp_check', timeout=60*15)
    def check_smtp(self, smtp_id, proxy_id=None):
        try:
            smtp = SMTP.objects.get(id=smtp_id)
            proxy = Proxy.objects.get(id=proxy_id) if proxy_id else None
            
            # Start background check
            task = check_smtp_task.delay(smtp.id, proxy.id if proxy else None)
            
            return Response({
                'task_id': task.id,
                'status': 'started'
            })
            
        except SMTP.DoesNotExist:
            return Response(
                {'error': 'SMTP not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"SMTP check failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ProxyCheckView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [CheckRateThrottle]

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Check Proxy',
        description='Check proxy server availability and functionality',
        responses={
            200: openapi.Response(
                description='Success',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: openapi.Response(
                description='Not found',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            500: openapi.Response(
                description='Internal server error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }    )
    @cache_result('proxy_check', timeout=60*15)
    def check_proxy(self, proxy_id):
        try:
            proxy = Proxy.objects.get(id=proxy_id)
            
            # Start background check
            task = check_proxy_task.delay(proxy.id)
            
            return Response({
                'task_id': task.id,
                'status': 'started'
            })
            
        except Proxy.DoesNotExist:
            return Response(
                {'error': 'Proxy not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Proxy check failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# SMTP Views
class SMTPListView(generics.ListAPIView):
    """API endpoint for getting SMTP servers list"""
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['smtp'],
        summary='List SMTP servers',
        description='Get list of all SMTP servers',
        responses={
            200: SMTPSerializer(many=True),
        }
    )
    def get(self, request):
        smtps = SMTP.objects.all()
        serializer = self.serializer_class(smtps, many=True)
        return Response(serializer.data)

class SMTPCreateView(generics.CreateAPIView):
    """Create SMTP server"""
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['smtp'],
        summary='Create SMTP',
        description='Create new SMTP server',
        request_body=SMTPSerializer,
        responses={
            201: SMTPSerializer,
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

class SMTPRetrieveView(generics.RetrieveAPIView):
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]
    queryset = SMTP.objects.all()

class SMTPUpdateView(generics.UpdateAPIView):
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]
    queryset = SMTP.objects.all()

class SMTPDeleteView(generics.DestroyAPIView):
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]
    queryset = SMTP.objects.all()


# Proxy Views
class ProxyListCreateView(APIView):
    """API endpoint for managing proxy servers"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['proxy'],
        summary='List proxies',
        description='Get list of all proxy servers',
        responses={
            200: ProxySerializer(many=True),
        }
    )
    def get(self, request):
        proxies = Proxy.objects.all()
        serializer = ProxySerializer(proxies, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Create proxy',
        description='Add new proxy server',
        request_body=ProxySerializer,
        responses={
            201: ProxySerializer,
        }
    )
    def post(self, request):
        serializer = ProxySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProxyDetailView(APIView):
    """API endpoint for managing individual proxy server"""
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Proxy.objects.get(pk=pk)
        except Proxy.DoesNotExist:
            raise Http404

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Get proxy',
        description='Get information about specific proxy server',
        responses={
            200: ProxySerializer,
        }
    )
    def get(self, request, pk):
        proxy = self.get_object(pk)
        serializer = ProxySerializer(proxy)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Update proxy',
        description='Update proxy server information',
        request_body=ProxySerializer,
        responses={
            200: ProxySerializer,
            400: openapi.Response(
                description='Bad Request',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: openapi.Response(
                description='Not Found',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }    )
    def put(self, request, pk):
        proxy = self.get_object(pk)
        serializer = ProxySerializer(proxy, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Delete proxy',
        description='Delete proxy server',
        responses={
            204: openapi.Response(
                description='No Content',
                schema=openapi.Schema(type=openapi.TYPE_OBJECT)
            ),
            404: openapi.Response(
                description='Not Found',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }    )
    def delete(self, request, pk):
        proxy = self.get_object(pk)
        proxy.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProxyCheckView(APIView):
    """API endpoint for checking proxy server"""
    permission_classes = [IsAuthenticated]
    throttle_classes = [CheckRateThrottle]

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Check proxy',
        description='Start proxy server health check',
        responses={
            200: openapi.Response(
                description='Check started',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: openapi.Response(
                description='Proxy not found',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def post(self, request, pk):
        try:
            proxy = Proxy.objects.get(pk=pk)
            task = check_proxy_task.delay(proxy.id)
            return Response({
                'task_id': task.id,
                'status': 'started'
            })
        except Proxy.DoesNotExist:
            return Response(
                {'error': 'Proxy not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


# Monitoring Views
class MetricsView(APIView):
    """API endpoint for getting Prometheus metrics"""
    permission_classes = []

    @swagger_auto_schema(
        tags=['monitoring'],
        summary='Prometheus metrics',
        description='Get metrics in Prometheus format',
        responses={
            200: openapi.Response(
                description='Metrics in Prometheus format',
                schema=openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Raw Prometheus metrics data'
                )
            )
        }
    )
    def get(self, request):
        metrics_page = generate_latest()
        return HttpResponse(
            metrics_page,
            content_type=CONTENT_TYPE_LATEST
        )
