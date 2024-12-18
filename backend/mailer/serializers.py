from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *

class BaseSerializer(serializers.ModelSerializer):
    class Meta:
        abstract = True
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')

class SessionSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Session

class SettingSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Setting

class SMTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = SMTP
        fields = ['id', 'server', 'port', 'email', 'password', 'status']
        extra_kwargs = {
            'server': {'help_text': 'SMTP сервер (например, smtp.gmail.com)'},
            'port': {'help_text': 'Порт SMTP сервера (например, 587)'},
            'email': {'help_text': 'Email адрес для аутентификации'},
            'password': {
                'help_text': 'Пароль или API ключ',
                'write_only': True
            },
            'status': {'help_text': 'Статус проверки (valid/invalid)'},
        }

class IMAPSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = IMAP

class ProxySerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Proxy

class BaseEmailSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Base

class DomainSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Domain

class TemplateSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Template

class LogSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Log

class TokenSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = Token

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(help_text="Имя пользователя")
    password = serializers.CharField(help_text="Пароль", style={'input_type': 'password'})

    class Meta:
        ref_name = 'Login'

class TokenResponseSerializer(serializers.Serializer):
    token = serializers.CharField(help_text="Токен доступа")

    class Meta:
        ref_name = 'TokenResponse'

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm')
        ref_name = 'Register'

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Пароли не совпадают")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class MaterialCheckSerializer(serializers.Serializer):
    type = serializers.ChoiceField(
        choices=['smtp', 'proxy', 'imap'],
        help_text="Тип материала для проверки"
    )
    session = serializers.CharField(help_text="Имя сессии")
    socket_id = serializers.CharField(help_text="ID веб-сокета")

    class Meta:
        ref_name = 'MaterialCheck'

class MailingRequestSerializer(serializers.Serializer):
    session = serializers.CharField(help_text="Имя сессии")
    template_id = serializers.IntegerField(help_text="ID шаблона")
    smtp_id = serializers.IntegerField(help_text="ID SMTP сервера")
    proxy_id = serializers.IntegerField(required=False, help_text="ID прокси")
    test_mode = serializers.BooleanField(default=False, help_text="Тестовый режим")
    test_email = serializers.EmailField(required=False, help_text="Email для тестовой отправки")

    class Meta:
        ref_name = 'MailingRequest'

class MailingResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    message = serializers.CharField()

    class Meta:
        ref_name = 'MailingResponse'

class LogClearRequestSerializer(serializers.Serializer):
    session = serializers.CharField(help_text="Имя сессии")

    class Meta:
        ref_name = 'LogClearRequest'

class MassMailingRequestSerializer(serializers.Serializer):
    session = serializers.CharField(help_text="Имя сессии")
    template_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="Список ID шаблонов"
    )
    smtp_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="Список ID SMTP серверов"
    )
    proxy_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Список ID прокси"
    )
    base_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="Список ID баз email"
    )
    socket_id = serializers.CharField(help_text="ID веб-сокета")
    delay = serializers.FloatField(default=0.3, help_text="Задержка между отправками")
    max_workers = serializers.IntegerField(default=5, help_text="Максимальное количество потоков")

    class Meta:
        ref_name = 'MassMailingRequest'

class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField(help_text="Файл для загрузки")
    session = serializers.CharField(help_text="Имя сессии")
    
    class Meta:
        ref_name = 'FileUpload'

class IPBlacklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPBlacklist
        fields = ['id', 'ip', 'reason', 'attempts', 'blocked_until', 'created_at', 'updated_at']
        read_only_fields = ['attempts', 'created_at', 'updated_at']

class MaterialSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    session = serializers.CharField()
    status = serializers.CharField(required=False)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)

    class Meta:
        abstract = True

