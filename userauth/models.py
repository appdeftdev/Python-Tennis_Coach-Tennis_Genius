from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField
from django.core.validators import FileExtensionValidator

from utils.models import BaseModel
from .managers import CustomUserManager

import random
from datetime import datetime, timedelta


ROLE_TYPES = (
    ("USER", "user"),
    ("ADMIN", "admin"),
    ("SUPER ADMIN", "super_admin")
)

LOGIN_TYPES = (
    ("manual", "manual"),
    ("google", "google"),
    ("facebook", "facebook"),
    ("apple", "apple"),
)

# Custom User model
class CustomUser(AbstractUser, BaseModel):
    email = models.EmailField(
        _('email address'), unique=True, max_length=200, blank=False, null=False)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_TYPES, default="SUPER ADMIN")
    phone = models.CharField(max_length=15, null=True, blank=True)
    country = models.CharField(max_length=30, null=True, blank=True)
    social_id = models.CharField(max_length=100, blank=True, null=True)
    login_type = models.CharField(
        max_length=20, choices=LOGIN_TYPES, default="manual")
    profile_pic = models.ImageField(upload_to='media/',blank=True,null=True,validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])
        ])
    stripe_customer_id=models.CharField(max_length=150,blank=True,null=True)
    # is_deleted = models.BooleanField(default=False)
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def save(self, *args, **kwargs):
        self.email = self.email.lower()  # Ensure emails are case-insensitive
        super(CustomUser, self).save(*args, **kwargs)

    @property
    def full_name(self):
        """Return the user's full name by combining first and last names."""
        return f"{self.first_name} {self.last_name}"


# OTP Model for handling one-time passwords (2FA)

class OTP(models.Model):
    PURPOSE_CHOICES = [
        ('LOGIN', 'Login'),
        ('RESET_PASSWORD', 'Reset Password'),
        ('TWO_FACTOR', 'Two Factor Authentication'),
        ('EMAIL_VERIFICATION', 'Email Verification'),
        ('DELETE_ACCOUNT', 'DELETE_ACCOUNT'),
    ]
    
    email = models.EmailField(max_length=200, null=False, blank=False)
    otp_code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=50, choices=PURPOSE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.otp_code:
            self.otp_code = self.generate_otp_code()
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=5)  # OTP valid for 5 minutes
        super(OTP, self).save(*args, **kwargs)

    def generate_otp_code(self):
        """Generates a 6-digit random OTP code."""
        return f"{random.randint(100000, 999999)}"

    def is_valid(self):
        """Check if the OTP is still valid (not expired)."""
        return timezone.now() <= self.expires_at and not self.verified

    def verify(self, otp_code):
        """
        Verifies if the given OTP matches and marks it as verified.
        """
        if self.is_valid() and self.otp_code == otp_code:
            self.verified = True
            self.save()
            return True
        return False

    @classmethod
    def send_otp(cls, email, purpose):
        """
        Send a new OTP to the user for a specific purpose, invalidate the old one.
        """
        email = email.lower()
        # Invalidate any existing OTPs for the same email and purpose
        cls.objects.filter(email=email,verified=False, purpose=purpose, expires_at__gt=timezone.now()).delete()
        print(">>>>>>>>>>>>>>>>>>>")
        # Generate and send a new OTP for the given purpose
        new_otp = cls(email=email, purpose=purpose)
        new_otp.save()

        # Send the OTP (e.g., via email, SMS, etc.)
        print(f"OTP {new_otp.otp_code} sent to {email} for {purpose}")
        return new_otp



class AccessToken(models.Model):
    token = models.CharField(max_length=500, unique=True)
    user = models.OneToOneField('CustomUser', on_delete=models.CASCADE)
    expires_at = models.DateTimeField(db_index=True)  # Indexed for faster lookups

    def __str__(self):
        return f"Active Token: {self.token[:20]}..."  # Display a shortened token

    def is_expired(self):
        """Check if the token is expired."""
        return timezone.now() >= self.expires_at

   
    
