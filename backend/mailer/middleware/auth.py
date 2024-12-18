from django.http import JsonResponse
from ..models import Token

class TokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.public_paths = [
            '/api/authentication/login/',
            '/api/authentication/register/',
            '/admin/',
            '/api/docs/',
            '/api/schema/',
            '/metrics',
            '/api/metrics/',
            '/api/redoc/',
            '/',
        ]

    def __call__(self, request):
        # Проверяем, является ли путь публичным
        if any(request.path.startswith(path) for path in self.public_paths):
            return self.get_response(request)

        # Для всех остальных путей проверяем токен
        token = request.headers.get('Authorization')
        if not token:
            return JsonResponse(
                {'error': 'Token is required'}, 
                status=401
            )
        
        token_obj = Token.objects.filter(token=token).first()
        if not token_obj:
            return JsonResponse(
                {'error': 'Invalid token'}, 
                status=401
            )
            
        request.user = token_obj.user
        return self.get_response(request) 