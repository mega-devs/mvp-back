from django.db import models
from django.contrib.auth.models import User

class Base(models.Model):
    first = models.CharField(max_length=255, null=True)
    last = models.CharField(max_length=255, null=True)
    email = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)

class Domain(models.Model):
    url = models.TextField(null=True)
    status = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)
    tempName = models.CharField(max_length=255, null=True)
    template = models.ForeignKey('Template', on_delete=models.SET_NULL, null=True)

class Manifest(models.Model):
    name = models.CharField(max_length=255, null=True)
    type = models.CharField(max_length=255, null=True)

class Material(models.Model):
    manifest = models.CharField(max_length=255, null=True)
    data = models.TextField(null=True)

class Proxy(models.Model):
    ip = models.CharField(max_length=255, null=True)
    port = models.CharField(max_length=255, null=True)
    status = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)

class Session(models.Model):
    name = models.CharField(max_length=255, null=True)

class SMTP(models.Model):
    server = models.CharField(max_length=255, null=True)
    port = models.CharField(max_length=255, null=True)
    email = models.CharField(max_length=255, null=True)
    password = models.CharField(max_length=255, null=True)
    status = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)

class Template(models.Model):
    maintmp = models.IntegerField(null=True)
    template = models.TextField(null=True)
    froms = models.TextField(null=True)
    subject = models.TextField(null=True)
    status = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)
    htmlbodies = models.TextField(null=True)

class Temp(models.Model):
    tempName = models.CharField(max_length=255, null=True)
    status = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)

class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, null=True)

class Log(models.Model):
    text = models.TextField(null=True)
    type = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)
    status = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class IMAP(models.Model):
    server = models.CharField(max_length=255, null=True)
    port = models.CharField(max_length=255, null=True)
    email = models.CharField(max_length=255, null=True)
    password = models.CharField(max_length=255, null=True)
    status = models.CharField(max_length=255, null=True)
    session = models.CharField(max_length=255, null=True)

class Setting(models.Model):
    session = models.CharField(max_length=255)
    type = models.CharField(max_length=255)
    data = models.IntegerField(null=True)

    class Meta:
        unique_together = ('session', 'type') 