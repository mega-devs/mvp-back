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

class SMTPSerializer(BaseSerializer):
    class Meta(BaseSerializer.Meta):
        model = SMTP

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

