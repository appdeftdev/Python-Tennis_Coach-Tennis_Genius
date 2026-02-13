from rest_framework import serializers

from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.conf import settings

from .models import CustomUser, OTP


class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=OTP.PURPOSE_CHOICES)

    def validate(self, data):
        """Ensure that the email belongs to an existing user or raises an error for signup purposes."""
        email = data['email'].lower().strip()
        purpose = data['purpose']
        
        if purpose == 'EMAIL_VERIFICATION':  # Ensure 'EMAIL_VERIFICATION' is correctly referenced
            if CustomUser.objects.filter(email=email).exists() and OTP.objects.filter(email=email, verified=True, purpose='EMAIL_VERIFICATION').exists():
                raise serializers.ValidationError("A user with this email already exists.")
        elif purpose in ['RESET_PASSWORD', 'DELETE_ACCOUNT']:
            
            if not CustomUser.objects.filter(email=email).exists():
                raise serializers.ValidationError("No user found with this email.")
        return data 


# Serializer for verifying OTP and signing up
class SignupSerializer(serializers.ModelSerializer):
    otp_code = serializers.CharField(max_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=50, write_only=True)
    full_name = serializers.CharField(max_length=200,write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['email', 'password','otp_code', 'confirm_password','full_name','phone','country']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    def validate_email(self, value):
        """Validate that the email does not already exist."""
        
        if CustomUser.objects.filter(email=value.lower()).exists() and OTP.objects.filter(email=value.lower(),verified=True,purpose='EMAIL_VERIFICATION').exists():
            raise ValidationError("A user with this email already exists.")
        return value
    
    def create(self, validated_data):
        
        parts = validated_data.pop('full_name').split()

        # Handle cases with more than one part
        first_name = parts[0]
        last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''
   
        
        """Create or update the user after OTP verification and set email_verified = True."""
        password = validated_data.pop('password')
        validated_data.pop('confirm_password')  # Remove confirm_password from validated data

        # Ensure the email is unique and handle creation or update
        email = validated_data.get('email')

        # Use update_or_create to either create a new user or update the existing one based on email
        user, created = CustomUser.objects.update_or_create(
            email=email.lower(),  # Normalize the email to lowercase
            first_name=first_name,
            last_name=last_name,
            phone=validated_data.get('phone', ''),
            country=validated_data.get('country', '')
        )

        # Set the password securely (only when the user is newly created or if it's being updated)
        if created or 'password' in validated_data:
            user.set_password(password)  # Hash the password securely

        # Save the user (in case password has changed)
        user.save()

        return user

class UserDetailSerializer(serializers.ModelSerializer):
    profile_pic = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    class Meta:
        model = CustomUser
        fields = ['email','full_name','phone','profile_pic','country']
    
    def get_full_name(self,instance):
        return instance.first_name + " " + instance.last_name
    
    def get_profile_pic(self, obj):
        request = self.context.get('request')
        print(request)
        if obj.profile_pic:
            return request.build_absolute_uri(obj.profile_pic.url) if request else settings.MEDIA_URL + obj.profile_pic.url
        return None
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        """Custom validation logic."""
        email = data.get('email').lower().strip()
        password = data.get('password')

        # Check if user with given email exists
        user = CustomUser.objects.filter(email=email).first()
        if user is None:
            raise serializers.ValidationError({"email": _("User with this email does not exist.")})

        # If user exists, check the password
        if not user.check_password(password):
            raise serializers.ValidationError({"password": _("Invalid password.")})

        # Return validated data if everything is correct
        return {
            'email': email,  # Return normalized email
            'password': password
        }
    

class UserProfileSerializer(serializers.ModelSerializer):
    profile_pic = serializers.ImageField(required=False)
    full_name = serializers.CharField(max_length=200, write_only=True, required=False)

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'phone', 'role', 'profile_pic', 'country', 'full_name']
        read_only_fields = ['email', 'role']  # Prevent updating email or role
    
    # def get_profile_pic(self, obj):
    #     """Generate full URL for profile picture"""
    #     request = self.context.get('request')
    #     if obj.profile_pic:
    #         return request.build_absolute_uri(obj.profile_pic.url) if request else settings.MEDIA_URL + obj.profile_pic.url
    #     return None
    
    def update(self, instance, validated_data):
        """Update user profile details"""
        full_name = validated_data.pop('full_name', None)

        # Update first_name and last_name from full_name if provided
        if full_name:
            parts = full_name.split()
            instance.first_name = parts[0]
            instance.last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''

        # Update other fields
        instance.phone = validated_data.get('phone', instance.phone)
        instance.country = validated_data.get('country', instance.country)
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",validated_data)
        # Handle profile picture update
        if 'profile_pic' in validated_data:
            print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",validated_data)
            instance.profile_pic = validated_data.get('profile_pic')

        instance.save()
        return instance
    


