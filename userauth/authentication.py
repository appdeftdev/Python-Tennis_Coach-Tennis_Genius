from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken as SimpleJWTAccessToken
from rest_framework.exceptions import APIException

from .models import AccessToken
from utils.helpers import success, error
from .exceptions import CustomAuthenticationFailed

        
class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        """Authenticate user while ensuring only the latest valid token is used."""
        header = self.get_header(request)
        if header is None:
            return None  # No Authorization header present

        raw_token = self.get_raw_token(header)
        if isinstance(raw_token, bytes):
            raw_token = raw_token.decode("utf-8")  # Convert bytes to string

        if raw_token is None:
            return None  # No token found in header
        
        # Check if the token exists in the database
        try:
             # Decode the token to extract JTI
            decoded_token = SimpleJWTAccessToken(raw_token)
            jti = decoded_token["jti"]  # Extract JTI

            # Check if the token exists in the database using JTI
            access_token = AccessToken.objects.get(token=jti)
        except AccessToken.DoesNotExist:
            raise CustomAuthenticationFailed("Invalid or expired token. Please log in again.")
        except Exception as e:
            raise CustomAuthenticationFailed(f"{str(e)}")
        
        # Ensure the token is not expired
        if access_token.is_expired():
            access_token.delete()  # Remove expired token
            raise CustomAuthenticationFailed("Token has expired. Please log in again.")

        return super().authenticate(request)  # Correctly return user & token


