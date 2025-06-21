import jwt
from django.http import JsonResponse
from django.conf import settings

EXCLUDED_PATHS = [
    '/', '/signup/', '/api/login/', '/check_email_availability/', '/logout/', '/isloggedin/',
]

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path not in EXCLUDED_PATHS:
            auth = request.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                token = auth.split(' ')[1]
                try:
                    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                    
                    request.user_email = payload.get('email')
                except jwt.ExpiredSignatureError:
                    return JsonResponse({'detail': 'Session expired'}, status=401)
                except jwt.InvalidTokenError:
                    return JsonResponse({'detail': 'Invalid token'}, status=401)
            else:
                return JsonResponse({'detail': 'Missing or invalid token'}, status=401)

        return self.get_response(request)
