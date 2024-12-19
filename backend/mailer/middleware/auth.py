from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication

class TokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()
        self.public_paths = [
            '/api/authentication/login/',
            '/api/authentication/register/',
            '/api/authentication/refresh/',
            '/admin/',
            '/api/docs/',
            '/api/schema/',
            '/metrics/',
            '/api/redoc/',
            '/api/swagger/',
            '/swagger/',
            '/',
        ]

    def __call__(self, request):
        if any(request.path.startswith(path) for path in self.public_paths):
            return self.get_response(request)

        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return JsonResponse(
                    {'error': 'Authorization header is required'}, 
                    status=401
                )

            validated_token = self.jwt_auth.get_validated_token(
                self.jwt_auth.get_raw_token(auth_header)
            )
            request.user = self.jwt_auth.get_user(validated_token)
            
        except Exception as e:
            return JsonResponse(
                {'error': str(e)}, 
                status=401
            )

        return self.get_response(request) 