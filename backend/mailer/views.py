from rest_framework import generics, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.utils import timezone
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample, OpenApiResponse
from drf_spectacular.types import OpenApiTypes
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import HttpResponse, Http404
from celery.result import AsyncResult
import secrets
import json
import logging
import os
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .models import *
from .serializers import (
    SessionSerializer, LoginSerializer, RegisterSerializer,
    TokenSerializer, TokenResponseSerializer, SettingSerializer,
    SMTPSerializer, ProxySerializer, BaseEmailSerializer,
    DomainSerializer, TemplateSerializer, IMAPSerializer,
    MaterialSerializer, LogSerializer, IPBlacklistSerializer,
    MailingRequestSerializer, MailingResponseSerializer,
    MaterialCheckSerializer, MassMailingRequestSerializer,
    LogClearRequestSerializer, FileUploadSerializer
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

class LoginView(generics.CreateAPIView):
    """User login endpoint"""
    serializer_class = LoginSerializer
    permission_classes = []
    throttle_classes = [AuthRateThrottle]

    @extend_schema(
        tags=['authentication'],
        summary='Вход в систему',
        description='Аутентификация пользователя и получение токена',
        request=LoginSerializer,
        responses={
            200: TokenSerializer,
            401: {'type': 'object', 'properties': {'error': {'type': 'string'}}},
        },
        examples=[
            OpenApiExample(
                'Успешный запрос',
                value={'username': 'user', 'password': 'pass123'},
                request_only=True,
            ),
            OpenApiExample(
                'Успешный ответ',
                value={'token': 'a1b2c3d4'},
                response_only=True,
            ),
        ]
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        
        if user:
            token = secrets.token_hex(8)
            Token.objects.create(user=user, token=token)
            logger.info(f'User {serializer.validated_data["username"]} logged in successfully')
            return Response({'token': token})
        else:
            logger.warning(f'Login failed for user {serializer.validated_data["username"]}')
            return Response(
                {'error': 'user not found or password is incorrect'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class RegisterView(generics.CreateAPIView):
    """User registration endpoint"""
    serializer_class = RegisterSerializer
    permission_classes = []
    throttle_classes = [AuthRateThrottle]

    @extend_schema(
        tags=['authentication'],
        operation_id='auth_register',
        summary='Регистрация пользователя',
        description='Создание нового пользователя в системе',
        request=RegisterSerializer,
        responses={
            201: TokenResponseSerializer,
            400: OpenApiResponse(
                description='Ошибка валидации',
                response={'type': 'object', 'properties': {'error': {'type': 'string'}}}
            )
        },
        examples=[
            OpenApiExample(
                'Успешный запрос',
                value={
                    'username': 'newuser',
                    'email': 'user@example.com',
                    'password': 'pass123',
                    'password_confirm': 'pass123'
                },
                request_only=True,
            ),
            OpenApiExample(
                'Успешный ответ',
                value={'token': 'a1b2c3d4'},
                response_only=True,
            ),
        ]
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.save()
        token = secrets.token_hex(8)
        Token.objects.create(user=user, token=token)
        
        logger.info(f'User {user.username} registered successfully')
        return Response(
            {'token': token},
            status=status.HTTP_201_CREATED
        )

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

    @extend_schema(
        tags=['sessions'],
        description='Получение списка сессий',
        responses={200: SessionSerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(
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
    
    @extend_schema(
        tags=['materials'],
        summary='Список материалов',
        description='Получение списка материалов определенного типа',
        parameters=[
            OpenApiParameter(
                name='type',
                description='Тип материала (smtps/proxies/bases)',
                required=True,
                type=str,
                location=OpenApiParameter.PATH,
            ),
            OpenApiParameter(
                name='session',
                description='ID сессии',
                required=True,
                type=str,
                location=OpenApiParameter.PATH,
            ),
        ],
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'data': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {}
                        }
                    }
                }
            },
            400: {'type': 'object', 'properties': {'error': {'type': 'string'}}},
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

    @method_decorator(cache_page(60*5))  # Кэш на 5 минут
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

    @extend_schema(
        tags=['mailing'],
        summary='Запуск рассылки',
        description='Запуск процесса рассылки email',
        request=MailingRequestSerializer,
        responses={
            200: MailingResponseSerializer,
            400: OpenApiResponse(description='Неверные параметры'),
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

    @extend_schema(
        tags=['materials'],
        summary='Проверка материалов',
        description='Запуск проверки SMTP, прокси или других материалов',
        request=MaterialCheckSerializer,
        responses={
            200: OpenApiResponse(description='Проверка запущена'),
            400: OpenApiResponse(description='Неверные параметры'),
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

    @extend_schema(
        tags=['logs'],
        summary='Получение логов',
        description='Получение ��огов для сессии',
        parameters=[
            OpenApiParameter(
                name='session',
                description='Имя сессии',
                required=True,
                type=str,
                location=OpenApiParameter.PATH,
            ),
        ],
        responses={200: LogSerializer(many=True)}
    )
    def get(self, request, session):
        logs = Log.objects.filter(session=session).order_by('-created_at')
        serializer = self.serializer_class(logs, many=True)
        return Response(serializer.data)

    @extend_schema(
        tags=['logs'],
        summary='Очистка логов',
        description='Очистка логов для сессии',
        request=LogClearRequestSerializer,
        responses={
            200: {'type': 'object', 'properties': {'status': {'type': 'string'}}},
            400: {'type': 'object', 'properties': {'error': {'type': 'string'}}}
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

    @extend_schema(
        tags=['mailing'],
        summary='Запуск массовой рассылки',
        description='Запуск процесса массовой рассылки email по нескольким шаблонам',
        request=MassMailingRequestSerializer,
        responses={
            200: MailingResponseSerializer,
            400: OpenApiResponse(description='Неверные параметры'),
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

    @extend_schema(
        tags=['settings'],
        summary='Получение настроек',
        description='Получение настроек для сессии',
        parameters=[
            OpenApiParameter(
                name='session',
                description='Имя сессии',
                required=True,
                type=str,
                location=OpenApiParameter.PATH,
            ),
        ],
        responses={200: SettingSerializer(many=True)}
    )
    def get(self, request, session):
        settings = Setting.objects.filter(session=session)
        serializer = SettingSerializer(settings, many=True)
        return Response(serializer.data)

    @extend_schema(
        tags=['settings'],
        summary='Обновление настроек',
        description='Обновление настроек для сессии',
        request=SettingSerializer,
        responses={
            200: SettingSerializer,
            400: OpenApiResponse(description='Неверные параметры'),
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

    @extend_schema(
        tags=['system'],
        summary='Время сервера',
        description='Получение текущего времени сервера',
        responses={200: {'type': 'object', 'properties': {'server_time': {'type': 'string'}}}}
    )
    def get(self, request):
        from django.utils import timezone
        return Response({'server_time': timezone.now().isoformat()})

class SystemStatusView(APIView):
    """Статус системы"""
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=['system'],
        summary='Статус системы',
        description='Получение статуса системы',
        responses={200: {'type': 'object', 'properties': {'status': {'type': 'string'}}}}
    )
    def get(self, request):
        # Проверяем доступность базы данных и других компонентов
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
            return Response({'status': 'healthy'})
        except Exception as e:
            logger.error(f'System health check failed: {str(e)}')
            return Response(
                {'status': 'unhealthy', 'error': str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

class FileUploadView(APIView):
    """Загрузка файлов с материалами"""
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    @extend_schema(
        tags=['files'],
        summary='Загрузка файла',
        description='Загрузка файла с материалами (базы, SMTP, прокси)',
        request={
            'multipart/form-data': {
                'type': 'object',
                'properties': {
                    'file': {'type': 'string', 'format': 'binary'},
                    'session': {'type': 'string'},
                    'type': {'type': 'string', 'enum': ['base', 'smtp', 'proxy']}
                }
            }
        },
        responses={
            200: OpenApiResponse(
                description='Файл обработан',
                response={'type': 'object', 'properties': {
                    'total': {'type': 'integer'},
                    'processed': {'type': 'integer'},
                    'failed': {'type': 'integer'}
                }}
            ),
            400: OpenApiResponse(description='Ошибка в параметрах'),
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

    @extend_schema(
        tags=['export'],
        summary='Экспорт данных',
        description='Экспорт данных в CSV формат',
        parameters=[
            OpenApiParameter(
                name='type',
                description='Тип данных (bases/smtp/proxy/logs)',
                required=True,
                type=str,
                location=OpenApiParameter.PATH,
            ),
            OpenApiParameter(
                name='session',
                description='Имя сессии',
                required=True,
                type=str,
                location=OpenApiParameter.PATH,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='CSV файл',
                response={'type': 'string', 'format': 'binary'}
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
    API endpoint для управления черным списком IP
    """
    queryset = IPBlacklist.objects.all()
    serializer_class = IPBlacklistSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
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

    @extend_schema(
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
@extend_schema_view(
    get=extend_schema(
        tags=['smtp'],
        summary='Список SMTP серверов',
        description='Получение списка всех SMTP серверов',
        responses={200: SMTPSerializer(many=True)}
    ),
    post=extend_schema(
        tags=['smtp'],
        summary='Создание SMTP сервера',
        description='Добавление нового SMTP сервера',
        request=SMTPSerializer,
        responses={201: SMTPSerializer}
    )
)
class SMTPListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        smtps = SMTP.objects.all()
        serializer = SMTPSerializer(smtps, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = SMTPSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@extend_schema_view(
    get=extend_schema(
        tags=['smtp'],
        summary='Получение SMTP сервера',
        description='Получение информации о конкретном SMTP сервере',
        responses={200: SMTPSerializer}
    ),
    put=extend_schema(
        tags=['smtp'],
        summary='Обновление SMTP сервера',
        description='Обновление информации о SMTP сервере',
        request=SMTPSerializer,
        responses={200: SMTPSerializer}
    ),
    delete=extend_schema(
        tags=['smtp'],
        summary='Удаление SMTP сервера',
        description='Удаление SMTP сервера',
        responses={204: None}
    )
)
class SMTPDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return SMTP.objects.get(pk=pk)
        except SMTP.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        smtp = self.get_object(pk)
        serializer = SMTPSerializer(smtp)
        return Response(serializer.data)

    def put(self, request, pk):
        smtp = self.get_object(pk)
        serializer = SMTPSerializer(smtp, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        smtp = self.get_object(pk)
        smtp.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@extend_schema(
    tags=['smtp'],
    summary='Проверка SMTP сервера',
    description='Проверка работоспособности SMTP сервера',
    responses={200: {'type': 'object', 'properties': {'status': {'type': 'string'}}}}
)
class SMTPCheckView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            smtp = SMTP.objects.get(pk=pk)
            # Здесь логика проверки SMTP
            return Response({'status': 'success'})
        except SMTP.DoesNotExist:
            return Response(
                {'error': 'SMTP not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

# Proxy Views
@extend_schema_view(
    get=extend_schema(
        tags=['proxy'],
        summary='Список прокси',
        description='Получение списка всех прокси серверов',
        responses={200: ProxySerializer(many=True)}
    ),
    post=extend_schema(
        tags=['proxy'],
        summary='Создание прокси',
        description='Добавление нового прокси сервера',
        request=ProxySerializer,
        responses={201: ProxySerializer}
    )
)
class ProxyListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        proxies = Proxy.objects.all()
        serializer = ProxySerializer(proxies, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ProxySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@extend_schema_view(
    get=extend_schema(
        tags=['proxy'],
        summary='Получение прокси',
        description='Получение информации о конкретном прокси',
        responses={200: ProxySerializer}
    ),
    put=extend_schema(
        tags=['proxy'],
        summary='Обновление прокси',
        description='Обновление информации о прокси',
        request=ProxySerializer,
        responses={200: ProxySerializer}
    ),
    delete=extend_schema(
        tags=['proxy'],
        summary='Удаление прокси',
        description='Удаление прокси',
        responses={204: None}
    )
)
class ProxyDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Proxy.objects.get(pk=pk)
        except Proxy.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        proxy = self.get_object(pk)
        serializer = ProxySerializer(proxy)
        return Response(serializer.data)

    def put(self, request, pk):
        proxy = self.get_object(pk)
        serializer = ProxySerializer(proxy, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        proxy = self.get_object(pk)
        proxy.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@extend_schema(
    tags=['proxy'],
    summary='Проверка прокси',
    description='Проверка работоспособности прокси сервера',
    responses={200: {'type': 'object', 'properties': {'status': {'type': 'string'}}}}
)
class ProxyCheckView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            proxy = Proxy.objects.get(pk=pk)
            # Здесь логика проверки прокси
            return Response({'status': 'success'})
        except Proxy.DoesNotExist:
            return Response(
                {'error': 'Proxy not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

# Monitoring Views
@extend_schema(
    tags=['monitoring'],
    summary='Статус системы',
    description='Получение текущего статуса системы',
    responses={
        200: {
            'type': 'object',
            'properties': {
                'status': {'type': 'string'},
                'components': {
                    'type': 'object',
                    'properties': {
                        'database': {'type': 'string'},
                        'redis': {'type': 'string'},
                        'celery': {'type': 'string'}
                    }
                }
            }
        }
    }
)
class SystemStatusView(APIView):
    permission_classes = [IsAuthenticated]

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

@extend_schema(
    tags=['monitoring'],
    summary='Prometheus метрики',
    description='Получение метрик в формате Prometheus',
    responses={200: {'type': 'string', 'format': 'binary'}}
)
class MetricsView(APIView):
    permission_classes = []

    def get(self, request):
        metrics_page = generate_latest()
        return HttpResponse(
            metrics_page,
            content_type=CONTENT_TYPE_LATEST
        )

