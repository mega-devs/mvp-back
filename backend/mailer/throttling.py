from rest_framework.throttling import SimpleRateThrottle
from django.core.cache import cache
from django.conf import settings

class CustomRateThrottle(SimpleRateThrottle):
    """
    Базовый класс для ограничения запросов
    """
    scope = 'custom'
    rate = '1000/day'
    cache = cache
    
    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
            
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }

class AuthRateThrottle(CustomRateThrottle):
    """
    Ограничение для аутентификации
    rate: 5/min
    """
    scope = 'auth'
    rate = '5/min'

class MailingRateThrottle(CustomRateThrottle):
    """
    Ограничение для рассылок
    rate: 2/min
    """
    scope = 'mailing'
    rate = '2/min'

class CheckRateThrottle(CustomRateThrottle):
    """
    Ограничение для проверок материалов
    rate: 10/min
    """
    scope = 'check'
    rate = '10/min'

class UploadRateThrottle(CustomRateThrottle):
    """
    Ограничение для загрузки файлов
    rate: 20/min
    """
    scope = 'upload'
    rate = '20/min' 