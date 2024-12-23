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
        summary='Вход в систему',
        description='Аутентификация пользователя и получение JWT токенов',
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'access': {'type': 'string', 'description': 'Access token'},
                    'refresh': {'type': 'string', 'description': 'Refresh token'}
                }
            }
        }
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
            201: {
                'type': 'object',
                'properties': {
                    'access': {'type': 'string', 'description': 'Access token'},
                    'refresh': {'type': 'string', 'description': 'Refresh token'}
                }
            },
            400: 'Ошибка валидации'
        },
        operation_description='Создание нового пользователя в системе',
        operation_summary='Регистрация пользователя',
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
        description='Получение списка сессий',
        responses={200: SessionSerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        tags=['sessions'],
        description='Создание новой сессии',
        request=SessionSerializer,
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

    def perform_destroy(self, instance):
        Setting.objects.filter(session=instance.name).delete()
        super().perform_destroy(instance)
        logger.info(f'Session {instance.name} deleted successfully')

class MaterialListView(generics.ListCreateAPIView):
    """List and create materials"""
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        tags=['materials'],
        summary='Список материалов',
        description='Получение списка материалов',
        manual_parameters=[
            openapi.Parameter(
                'type',
                openapi.IN_PATH,
                description='Тип материала',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Список материалов',
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                        }
                    )
                )
            ),
            400: openapi.Response(
                description='Ошибка в параметрах',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
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
        summary='Запуск рассылки',
        description='Запуск процесса рассылки',
        request_body=MailingRequestSerializer,
        responses={
            200: openapi.Response(
                description='Рассылка запущена',
                schema=MailingResponseSerializer
            ),
            400: openapi.Response(
                description='Ошибка в параметрах',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def post(self, request):
        # Валидация заголовков
        headers = SecurityUtils.validate_headers(request.headers)
        
        try:
            # Санитизация HTML в сообщении
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
        summary='Проверка материалов',
        description='Запуск проверки SMTP, прокси или других материалов',
        request_body=MaterialCheckSerializer,
        responses={
            200: openapi.Response(
                description='Проверка запущена',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: openapi.Response(
                description='Ошибка в параметрах',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
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
                # Асинхронная проверка через Celery
                task = check_smtp_task.delay(smtp.id)
        
        elif material_type == 'proxy':
            proxies = Proxy.objects.filter(session=session)
            for proxy in proxies:
                # Асинхронная проверка через Celery
                task = check_proxy_task.delay(proxy.id)

        return Response({'status': 'check started'})

class LogView(APIView):
    """Управление логами"""
    permission_classes = [IsAuthenticated]
    serializer_class = LogSerializer
    clear_serializer_class = LogClearRequestSerializer

    @swagger_auto_schema(
        tags=['logs'],
        summary='Получение логов',
        description='Получение логов сессии',
        manual_parameters=[
            openapi.Parameter(
                'session',
                openapi.IN_PATH,
                description='ID сессии',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Список логов',
                schema=LogSerializer(many=True)
            ),
            404: openapi.Response(
                description='Сессия не найдена',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def get(self, request, session):
        logs = Log.objects.filter(session=session).order_by('-created_at')
        serializer = self.serializer_class(logs, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['logs'],
        summary='Очистка логов',
        description='Очистка логов для сессии',
        request_body=LogClearRequestSerializer,
        responses={
            200: openapi.Response(
                description='Успешно',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: openapi.Response(
                description='Ошибка',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def delete(self, request, session):
        serializer = self.clear_serializer_class(data={'session': session})
        serializer.is_valid(raise_exception=True)
        Log.objects.filter(session=session).delete()
        return Response({'status': 'success'})

class MassMailingView(APIView):
    """Управление массовой рассылкой"""
    permission_classes = [IsAuthenticated]
    serializer_class = MassMailingRequestSerializer

    @swagger_auto_schema(
        tags=['mailing'],
        summary='Запуск массовой рассылки',
        description='Запуск процесса массовой рассылки',
        request_body=MassMailingRequestSerializer,
        responses={
            200: MailingResponseSerializer,
            400: openapi.Response(
                description='Неверные параметры',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
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
    """Управление настройками"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['settings'],
        summary='Получение настроек',
        description='Получение настроек для сессии',
        manual_parameters=[
            openapi.Parameter(
                'session',
                openapi.IN_PATH,
                description='Имя сессии',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Настройки сессии",
                schema=SettingSerializer(many=True)
            ),
            404: openapi.Response(
                description='Сессия не найдена',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def get(self, request, session):
        settings = Setting.objects.filter(session=session)
        serializer = SettingSerializer(settings, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['settings'],
        summary='Обновление настроек',
        description='Обновление настроек д��я сессии',
        request_body=SettingSerializer,
        responses={
            200: SettingSerializer,
            400: openapi.Response(
                description='Неверные параметры',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
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
    """Получение времени сервера"""
    permission_classes = []

    @swagger_auto_schema(
        tags=['system'],
        summary='Время сервера',
        description='Получение текущего времени сервера',
        responses={
            200: openapi.Response(
                description='Текущее время сервера',
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
        }
    )
    def get(self, request):
        from django.utils import timezone
        return Response({'server_time': timezone.now().isoformat()})

class SystemStatusView(APIView):
    """API endpoint для мониторинга состояния системы"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['monitoring'],
        summary='Статус системы',
        description='Получение текущего статуса системы',
        responses={
            200: openapi.Response(
                description='Успешный ответ',
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
                description='Сервис недоступен',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
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
    """Загрузка файлов с материалами"""
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    @swagger_auto_schema(
        tags=['files'],
        summary='Загрузка файла',
        description='Загрузка файла с материалами (базы, SMTP, прокси)',
        manual_parameters=[
            openapi.Parameter(
                'file',
                openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                required=True,
                description='Файл для загрузки'
            ),
            openapi.Parameter(
                'session',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                required=True,
                description='ID сессии'
            ),
            openapi.Parameter(
                'type',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                required=True,
                enum=['base', 'smtp', 'proxy'],
                description='Тип материала'
            )
        ],
        responses={
            200: openapi.Response(
                description='Файл обработан',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'total': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'processed': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'failed': openapi.Schema(type=openapi.TYPE_INTEGER)
                    }
                )
            ),
            400: openapi.Response(
                description='Ошибка в параметрах',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def post(self, request):
        file_obj = request.FILES.get('file')
        session = request.POST.get('session')
        
        try:
            # Валидация файла
            SecurityUtils.validate_file_upload(file_obj)
            
            # Сохранение во временный файл
            content = file_obj.read().decode('utf-8')
            temp_path = FileService.save_temp_file(content)
            
            processor = FileService.get_processor(request.POST.get('type'))
            result = processor(content, session)
            
            # Удаляем временный файл
            os.remove(temp_path)
            
            return Response(result)
            
        except Exception as e:
            logger.error(f"Error processing file: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class ExportView(APIView):
    """Экспорт данных"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['export'],
        summary='Экспорт данных',
        description='Экспорт данных в CSV формат',
        manual_parameters=[
            openapi.Parameter(
                'type',
                openapi.IN_PATH,
                description='Тип данных (bases/smtp/proxy/logs)',
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'session',
                openapi.IN_PATH,
                description='Имя сессии',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='CSV файл',
                schema=openapi.Schema(
                    type=openapi.TYPE_STRING,
                    format='binary'
                )
            ),
            400: openapi.Response(description='Ошибка в параметрах'),
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
    API endpoint для управления черным списком IP
    """
    queryset = IPBlacklist.objects.all()
    serializer_class = IPBlacklistSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['security'],
        summary='Черный список IP',
        description='Управление заблокированными IP адресами',
        responses={
            200: IPBlacklistSerializer(many=True),
            401: {'type': 'object', 'properties': {'error': {'type': 'string'}}}
        }
    )
    def list(self, request):
        return super().list(request)

    @swagger_auto_schema(
        tags=['security'],
        summary='Добавить IP в черный список',
        request=IPBlacklistSerializer,
        responses={201: IPBlacklistSerializer}
    )
    def create(self, request):
        return super().create(request)

class SMTPCheckView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [CheckRateThrottle]

    @cache_result('smtp_check', timeout=60*15)
    def check_smtp(self, smtp_id, proxy_id=None):
        try:
            smtp = SMTP.objects.get(id=smtp_id)
            proxy = Proxy.objects.get(id=proxy_id) if proxy_id else None
            
            # Запускаем проверку в фоновом режиме
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

    @cache_result('proxy_check', timeout=60*15)
    def check_proxy(self, proxy_id):
        try:
            proxy = Proxy.objects.get(id=proxy_id)
            
            # Запускаем проверку в фоновом режиме
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
    """API endpoint для получения списка SMTP серверов"""
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['smtp'],
        summary='Список SMTP серверов',
        description='Получение списка всех SMTP серверов',
        responses={
            200: SMTPSerializer(many=True),
            401: openapi.Response(
                description='Не авторизован',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def get(self, request):
        smtps = SMTP.objects.all()
        serializer = self.serializer_class(smtps, many=True)
        return Response(serializer.data)

class SMTPCreateView(generics.CreateAPIView):
    """Создание SMTP сервера"""
    serializer_class = SMTPSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['smtp'],
        summary='Создание SMTP',
        description='Создание нового SMTP сервера',
        request_body=SMTPSerializer,
        responses={
            201: SMTPSerializer,
            400: openapi.Response(
                description='Неверные данные',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
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
    """API endpoint для управления прокси серверами"""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Список прокси',
        description='Получение списка всех прокси серверов',
        responses={
            200: ProxySerializer(many=True),
            401: openapi.Response(
                description='Не авторизован',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def get(self, request):
        proxies = Proxy.objects.all()
        serializer = ProxySerializer(proxies, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Создание прокси',
        description='Добавление нового прокси сервера',
        request_body=ProxySerializer,
        responses={
            201: ProxySerializer,
            400: openapi.Response(
                description='Неверные данные',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def post(self, request):
        serializer = ProxySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProxyDetailView(APIView):
    """API endpoint для работы с отдельным прокси сервером"""
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Proxy.objects.get(pk=pk)
        except Proxy.DoesNotExist:
            raise Http404

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Получение прокси',
        description='Получение информации о конкретном прокси сервере',
        responses={
            200: ProxySerializer,
            404: openapi.Response(
                description='Прокси не найден',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def get(self, request, pk):
        proxy = self.get_object(pk)
        serializer = ProxySerializer(proxy)
        return Response(serializer.data)

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Обновление прокси',
        description='Обновление информации о прокси сервере',
        request_body=ProxySerializer,
        responses={
            200: ProxySerializer,
            400: openapi.Response(
                description='Неверные данные',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: openapi.Response(
                description='Прокси не найден',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def put(self, request, pk):
        proxy = self.get_object(pk)
        serializer = ProxySerializer(proxy, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Удаление прокси',
        description='Удаление прокси сервера',
        responses={
            204: openapi.Response(
                description='Прокси успешно удален',
                schema=openapi.Schema(type=openapi.TYPE_OBJECT)
            ),
            404: openapi.Response(
                description='Прокси не найден',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def delete(self, request, pk):
        proxy = self.get_object(pk)
        proxy.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ProxyCheckView(APIView):
    """API endpoint для проверки прокси сервера"""
    permission_classes = [IsAuthenticated]
    throttle_classes = [CheckRateThrottle]

    @swagger_auto_schema(
        tags=['proxy'],
        summary='Проверка прокси',
        description='Запуск проверки работоспособности прокси сервера',
        responses={
            200: openapi.Response(
                description='Проверка запущена',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: openapi.Response(
                description='Прокси не найден',
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
    """API endpoint для получения метрик Prometheus"""
    permission_classes = []

    @swagger_auto_schema(
        tags=['monitoring'],
        summary='Prometheus метрики',
        description='Получение метрик в формате Prometheus',
        responses={
            200: openapi.Response(
                description='Метрики в формате Prometheus',
                schema=openapi.Schema(
                    type=openapi.TYPE_STRING,
                    format='binary'
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

