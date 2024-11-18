# utils.py

import jwt
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

def get_email_from_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload.get('email')
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Token has expired')
    except jwt.DecodeError:
        raise AuthenticationFailed('Invalid token')
