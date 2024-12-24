from django.contrib import admin
from .models import Base, Domain, Manifest, Material, Proxy, Session, SMTP, Template, Temp, Log, IMAP, Setting, IPBlacklist

@admin.register(Base)
class BaseAdmin(admin.ModelAdmin):
    list_display = ('first', 'last', 'email', 'session', 'status')
    search_fields = ('email', 'session')
    list_filter = ('status',)

@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('url', 'status', 'session', 'tempName', 'template')
    search_fields = ('url', 'session')
    list_filter = ('status',)

@admin.register(Proxy)
class ProxyAdmin(admin.ModelAdmin):
    list_display = ('ip', 'port', 'status', 'session')
    search_fields = ('ip', 'session')
    list_filter = ('status',)

@admin.register(SMTP)
class SMTPAdmin(admin.ModelAdmin):
    list_display = ('server', 'port', 'email', 'status', 'session')
    search_fields = ('server', 'email', 'session')
    list_filter = ('status',)

@admin.register(Template)
class TemplateAdmin(admin.ModelAdmin):
    list_display = ('maintmp', 'status', 'session')
    search_fields = ('session',)
    list_filter = ('status',)

@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('text', 'type', 'session', 'status', 'created_at')
    search_fields = ('text', 'session')
    list_filter = ('type', 'status')
    readonly_fields = ('created_at',)

@admin.register(IMAP)
class IMAPAdmin(admin.ModelAdmin):
    list_display = ('server', 'port', 'email', 'status', 'session')
    search_fields = ('server', 'email', 'session')
    list_filter = ('status',)

@admin.register(Setting)
class SettingAdmin(admin.ModelAdmin):
    list_display = ('session', 'type', 'data')
    search_fields = ('session', 'type')
    list_filter = ('type',)

@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ('ip', 'reason', 'attempts', 'blocked_until', 'created_at', 'updated_at')
    search_fields = ('ip', 'reason')
    readonly_fields = ('created_at', 'updated_at')
    list_filter = ('blocked_until',)

admin.site.register(Manifest)
admin.site.register(Material)
admin.site.register(Session)
admin.site.register(Temp)
