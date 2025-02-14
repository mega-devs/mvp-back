from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
import logging

logger = logging.getLogger(__name__)

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
        fields = ['id', 'server', 'port', 'email', 'password', 'status', 'session']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        logger.info(f"Serializing SMTP instance: {instance.id}")
        return data

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

class LoginResponseSerializer(serializers.Serializer):
    token = serializers.CharField(help_text="JWT authentication token")
    user = UserSerializer(help_text="User details")

    class Meta:
        ref_name = 'LoginResponse'

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(help_text="Username")
    password = serializers.CharField(help_text="Password", style={'input_type': 'password'})

    class Meta:
        ref_name = 'Login'

class RegisterResponseSerializer(serializers.Serializer):
    message = serializers.CharField(help_text="Registration success message")
    user = UserSerializer(help_text="Created user details")

    class Meta:
        ref_name = 'RegisterResponse'

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm')
        ref_name = 'Register'

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class MaterialCheckResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField(help_text="Check result status")
    message = serializers.CharField(help_text="Detailed check result message")
    details = serializers.DictField(help_text="Additional check details", required=False)

    class Meta:
        ref_name = 'MaterialCheckResponse'

class MaterialCheckSerializer(serializers.Serializer):
    type = serializers.ChoiceField(
        choices=['smtp', 'proxy', 'imap'],
        help_text="Material type to check"
    )
    session = serializers.CharField(help_text="Session name")
    socket_id = serializers.CharField(help_text="WebSocket ID")

    class Meta:
        ref_name = 'MaterialCheck'

class MailingRequestSerializer(serializers.Serializer):
    session = serializers.CharField(help_text="Session name")
    template_id = serializers.IntegerField(help_text="Template ID")
    smtp_id = serializers.IntegerField(help_text="SMTP server ID")
    proxy_id = serializers.IntegerField(required=False, help_text="Proxy ID")
    test_mode = serializers.BooleanField(default=False, help_text="Test mode flag")
    test_email = serializers.EmailField(required=False, help_text="Test email address")

    class Meta:
        ref_name = 'MailingRequest'

class MailingResponseSerializer(serializers.Serializer):
    status = serializers.CharField(help_text="Operation status")
    message = serializers.CharField(help_text="Operation result message")
    details = serializers.DictField(help_text="Additional operation details", required=False)

    class Meta:
        ref_name = 'MailingResponse'

class LogClearResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField(help_text="Operation success status")
    message = serializers.CharField(help_text="Operation result message")

    class Meta:
        ref_name = 'LogClearResponse'

class LogClearRequestSerializer(serializers.Serializer):
    session = serializers.CharField(help_text="Session name")

    class Meta:
        ref_name = 'LogClearRequest'

class MassMailingResponseSerializer(serializers.Serializer):
    task_id = serializers.CharField(help_text="Background task ID")
    status = serializers.CharField(help_text="Task initial status")
    message = serializers.CharField(help_text="Operation message")

    class Meta:
        ref_name = 'MassMailingResponse'

class MassMailingRequestSerializer(serializers.Serializer):
    session = serializers.CharField(help_text="Session name")
    template_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of template IDs"
    )
    smtp_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of SMTP server IDs"
    )
    proxy_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of proxy IDs"
    )
    base_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of email base IDs"
    )
    socket_id = serializers.CharField(help_text="WebSocket ID")
    delay = serializers.FloatField(default=0.3, help_text="Delay between sends")
    max_workers = serializers.IntegerField(default=5, help_text="Maximum number of threads")

    class Meta:
        ref_name = 'MassMailingRequest'

class FileUploadResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField(help_text="Upload success status")
    message = serializers.CharField(help_text="Operation result message")
    file_info = serializers.DictField(help_text="Uploaded file information", required=False)

    class Meta:
        ref_name = 'FileUploadResponse'

class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField(help_text="File to upload")
    session = serializers.CharField(help_text="Session name")
    
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
