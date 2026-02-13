from rest_framework.exceptions import APIException
from rest_framework import status

class CustomAuthenticationFailed(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Authentication failed. Please log in again."
    default_code = "authentication_failed"

    def __init__(self, detail=None, data=None):
        if detail is None:
            detail = self.default_detail
        if data is None:
            data = {}

        self.detail = {
            "success": False,
            "message": detail,
            "data": data
        }
