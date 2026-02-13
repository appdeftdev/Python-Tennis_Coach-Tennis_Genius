from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.core.exceptions import ValidationError
from django.contrib.auth import logout

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from fcm_django.models import FCMDevice
from utils.emailTemplates import send_forgot_password_email,send_verification_email,send_two_factor_email,send_delete_account_email
from utils.helpers import success, error, error_handler,generate_password
from .utilis.auth import generate_user_token, generate_jwt_token
from .models import CustomUser, OTP,AccessToken
from .serializers import (OTPRequestSerializer, SignupSerializer, LoginSerializer,
                          UserProfileSerializer,UserDetailSerializer)


from notification.views import send_notification
import random


def verify_otp_function(email, otp_code, verification_type):
    """Function to verify OTP for a given email and purpose."""
    if not otp_code or not email:
        return Response(error(error_handler("OTP and email are required."), {}), 
                        status=status.HTTP_400_BAD_REQUEST)
    # Verify the OTP
    try:
        # print(OTP.objects.filter)
        print(">>>>>>>>>>>>>>>>",email,otp_code,verification_type)
        otp_instance = OTP.objects.get(email=email,otp_code=otp_code,verified=False,purpose=verification_type)
    
        if not otp_instance.is_valid():
            return Response(error(error_handler("OTP is expired or invalid."), {}), 
                            status=status.HTTP_400_BAD_REQUEST)
    except OTP.DoesNotExist:
        return Response(error(error_handler("Invalid OTP."), {}), 
                        status=status.HTTP_400_BAD_REQUEST)

    # Mark OTP as verifiedssss
    if not otp_instance.verify(otp_code):
        return Response(error(error_handler("Invalid OTP"), {}), 
                        status=status.HTTP_400_BAD_REQUEST)
    return Response(success("OTP Verified", {}), status=status.HTTP_200_OK)


# View for sending OTP to the email
class OTPRequestView(APIView):
    
    def post(self, request, *args, **kwargs):
        serializer = OTPRequestSerializer(data=request.data, context={'request': request})
        
        # Validate the serializer data
        if not serializer.is_valid():
            return Response(error(error_handler(serializer.errors), {}), status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        
        purpose = serializer.validated_data['purpose']
        
        # Generate and send OTP
        try:
            otp_obj = OTP.send_otp(email, purpose)  # Invalidates past OTPs and generates a new one
        except Exception as e:
            return Response(error(error_handler(f"Error generating OTP: {str(e)}"), {}), status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Send appropriate email based on purpose
        if purpose == "EMAIL_VERIFICATION":
            send_verification_email('Confirm your email', [email], otp_obj.otp_code)
        elif purpose == "RESET_PASSWORD":
            send_forgot_password_email('Confirm your email', [email], otp_obj.otp_code)
        elif purpose == "DELETE_ACCOUNT":
            send_delete_account_email('Confirm your email', [email], otp_obj.otp_code)
        elif purpose == 'TWO_FACTOR':
            send_two_factor_email('Two-factor authentication', [email], otp_obj.otp_code)

        return Response(success("OTP sent successfully.", {}), status=status.HTTP_200_OK)


# View for verifying OTP and signing up the user
class SignupView(APIView):

    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            otp_code = serializer.validated_data.pop('otp_code','')
            verification_type = 'EMAIL_VERIFICATION'
            email = serializer.validated_data['email'].lower()
            # Verify OTP
            otp_response = verify_otp_function(email, otp_code, verification_type)
            if otp_response.status_code != 200:  # OTP verification failed
                return otp_response

            password = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']
            # check password match with confirm password
            if password != confirm_password:
                return Response(error(error_handler("Confirm password does't match with password"),{}),
                                    status=status.HTTP_400_BAD_REQUEST)

            user = serializer.save()
            # send_verification_email('Confirm your email', [email], otp_obj.otp_code)
            # send token 
            # jwt_token_data = generate_jwt_token(user)
            
            return Response(success("User registered successfully", UserDetailSerializer(user,context={'request': request}).data), status=status.HTTP_201_CREATED)
        return Response(error(error_handler(serializer.errors), {}), status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
        
            # Get the validated credentials
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            email = email.lower()
            
            # Get the user first to check if they're admin-created
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(error("Invalid credentials.", {}), status=status.HTTP_401_UNAUTHORIZED)
            
            # Check password
            if not user.check_password(password):
                return Response(error("Invalid credentials.", {}), status=status.HTTP_401_UNAUTHORIZED)
            
            # Check OTP verification - skip for staff/superuser (admin-created users)
            # Regular users must have verified EMAIL_VERIFICATION OTP
            if not (user.is_staff or user.is_superuser):
                if not OTP.objects.filter(email=email, verified=True, purpose='EMAIL_VERIFICATION').exists():
                    return Response(error("Please complete otp verificatiion.", {}), status=status.HTTP_401_UNAUTHORIZED)
            
            # generate token
            jwt_token_data = generate_jwt_token(user)
            user_data=UserDetailSerializer(user,context={'request': request}).data
            response_data = {**user_data, **jwt_token_data}  
            return Response(success('Login successfully', response_data), status=status.HTTP_200_OK)
        return Response(error(error_handler(serializer.errors), {}), status=status.HTTP_400_BAD_REQUEST)
        
    
# OTP Verification View
class VerifyOtpView(APIView):
    def post(self, request):
        
        otp_code = str(request.data.get('otp_code',''))
        email = request.data.get('email','').lower()
        if not otp_code or not email:
            return Response(error(error_handler("OTP and email are required."), {}), 
                        status=status.HTTP_400_BAD_REQUEST)
        verification_type = request.data.get('verification_type')
        return verify_otp_function(email, otp_code, verification_type)
    

# Forgot password view
class ResetPasswordApiView(APIView):
    def post(self, request):
        email = request.data.get('email', "").lower()
        password = request.data.get('password', "")
        confirm_password = request.data.get('confirm_password', "")
        if not email:
            return Response(error(error_handler("Email is required."), {}),
                            status=status.HTTP_400_BAD_REQUEST)
        
        if not password or not confirm_password:
            return Response(error(error_handler("Password and Confirm Password are required."), {}),
                            status=status.HTTP_400_BAD_REQUEST)
            
        if password != confirm_password:
            return Response(error(error_handler("Password and Confirm Password did't matched."), {}),
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            user = CustomUser.objects.get(email=email)
            
        except (ValueError, CustomUser.DoesNotExist):
            return Response(error(error_handler("No user found with this email address."), {}), status=status.HTTP_400_BAD_REQUEST)
        otp = OTP.objects.filter(email=email,verified=True, purpose='RESET_PASSWORD').first()
        if not otp:
            return Response(error("Please complete otp verificatiion to reset password.", {}), status=status.HTTP_401_UNAUTHORIZED)
        
        # Ensure password is not the same as the current one
        if user.check_password(password):
            return Response(error(error_handler("New password cannot be the same as the old password."), {}),
                            status=status.HTTP_400_BAD_REQUEST)

        # changes password
        user.set_password(password)
        user.save()
        otp.delete()
        return Response(success('Passowrd reset sucessfully', {}), status=status.HTTP_200_OK)
    
     
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """Get the user's profile details."""
        user = request.user
        serializer = UserProfileSerializer(user, context={'request': request})
        return Response(success("success", UserDetailSerializer(user,context={'request': request}).data,), status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """Update the user's profile details."""
        user = request.user
        print(request.data)
        serializer = UserProfileSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()  # Update the user's profile
            send_notification("Your profile was updated successfully.", user)
            return Response(success("Profile updated sucessfully",UserDetailSerializer(user,context={'request': request}).data), status=status.HTTP_200_OK)
        return Response(error(error_handler(serializer.errors), {}), status=status.HTTP_400_BAD_REQUEST)
    

class SocialLoginAPI(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        email = data.get('email','').lower()
        social_id=data.get('social_id','')
        login_type=data.get('login_type','')
        first_name=data.get('first_name','')
        if not email:
            return Response(error("Email is required.", {}), status=status.HTTP_400_BAD_REQUEST)
        
        if not social_id:
            return Response(error("Social Id is required.", {}), status=status.HTTP_400_BAD_REQUEST)
        
        if not first_name:
            return Response(error("First Name is required.", {}), status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except ValidationError:
            return Response(error("Please enter a valid email.", {}), status=status.HTTP_400_BAD_REQUEST)
        try:
            # Use get_or_create to handle race conditions
            with transaction.atomic():
                user, created = CustomUser.objects.get_or_create(
                    email=email,
                    defaults={
                        "first_name": data.get('first_name', ''),
                        "last_name": data.get('last_name', ''),
                        "password": make_password(generate_password()),
                        "social_id": social_id,
                        "login_type": login_type,
                    }
                )
                
                #verified otp  created
                otp = f"{random.randint(100000, 999999)}"
                if created:
                    OTP.objects.create(email=email,otp_code=otp,verified=True,purpose='EMAIL_VERIFICATION').save()

                # Update user if already exists
                if not created:
                    user.first_name = data.get('first_name', user.first_name)
                    user.last_name = data.get('last_name', user.last_name)
                    user.social_id = social_id
                    user.login_type = login_type
                    user.email_verified = True
                    user.save()

                # generate token
                jwt_token_data = generate_jwt_token(user)
                user_data=UserDetailSerializer(user,context={'request': request}).data
                response_data = {**user_data, **jwt_token_data}  
                return Response(
                    success('Login successfully.', response_data),
                    status=status.HTTP_200_OK
                )
        
        except Exception as e:
            return Response(error(str(e), {}), status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            AccessToken.objects.filter(user=request.user).delete()
            return Response(success("Successfully logged out.", {}), status=status.HTTP_200_OK)

        except Exception as e:
            return Response(success(f"An unexpected error occurred: {str(e)}", {}), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        """Get the user's profile details."""
        user = request.user
        otp = OTP.objects.filter(email=user.email,verified=True, purpose='DELETE_ACCOUNT').first()
        if not otp:
            return Response(error("Please complete otp verificatiion to delete user account.", {}), status=status.HTTP_401_UNAUTHORIZED)
        user.delete()
        otp.delete()
        return Response(success("User deleted successfully", {}), status=status.HTTP_200_OK)
    
    
class ChangePasswordApiView(APIView):
    permission_classes = [IsAuthenticated]  # Ensures the user is authenticated
    
    def post(self, request):
        # Get current password, new password, and confirm password from the request
        current_password = request.data.get('current_password', "")
        new_password = request.data.get('new_password', "")
        confirm_password = request.data.get('confirm_password', "")

        # Validate required fields
        if not current_password or not new_password or not confirm_password:
            return Response(error(error_handler("Current password, new password, and confirm password are required."), {}),
                            status=status.HTTP_400_BAD_REQUEST)

        # Check if new password and confirm password match
        if new_password != confirm_password:
            return Response(error(error_handler("New password and confirm password didn't match."), {}),
                            status=status.HTTP_400_BAD_REQUEST)

        # Get the currently authenticated user
        user = request.user

        # Ensure current password is correct
        if not user.check_password(current_password):
            return Response(error(error_handler("Current password is incorrect."), {}),
                            status=status.HTTP_400_BAD_REQUEST)

        # Ensure new password is not the same as the old one
        if user.check_password(new_password):
            return Response(error(error_handler("New password cannot be the same as the old password."), {}),
                            status=status.HTTP_400_BAD_REQUEST)

        # Set the new password and save it
        user.set_password(new_password)
        user.save()

        # Return success response
        return Response(success('Password changed successfully', {}), status=status.HTTP_200_OK)
    
    
  # Adjust import path
class UpdateFCMTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        user = request.user

        fcm_token = data.get('fcm_token','')
        fcm_token_type = data.get('type', 'android')
        app_version = data.get('app_version', '')

        if not fcm_token:
            return Response(error('Token FCM no proporcionado', {}), status=status.HTTP_200_OK)

        device, created = FCMDevice.objects.get_or_create(
            registration_id=fcm_token,
            defaults={
                'user': user,
                'type': fcm_token_type,
                'name': app_version,
                'active': True
            }
        )

        if not created:
            updated = False
            if device.user != user:
                device.user = user
                updated = True
            if device.type != fcm_token_type:
                device.type = fcm_token_type
                updated = True
            if device.name != app_version:
                device.name = app_version
                updated = True
            if not device.active:
                device.active = True
                updated = True    

            if updated:
                device.save(update_fields=['user', 'type', 'name', 'active'])
            return Response(success('Token FCM actualizado correctamente', {}), status=status.HTTP_200_OK)
        return Response(success('Token FCM registrado exitosamente', {}), status=status.HTTP_200_OK)
