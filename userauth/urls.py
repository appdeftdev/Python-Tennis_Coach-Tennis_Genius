from django.urls import path
from userauth import views

urlpatterns = [
    path('send-otp/', views.OTPRequestView.as_view(), name='send-otp'),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
    path('verify-otp/', views.VerifyOtpView.as_view(), name='verify-otp'),
    path('forgot-password/', views.ResetPasswordApiView.as_view(), name='reset-password'),
    path('social-login/',views.SocialLoginAPI.as_view(),name='social-login'),
    path('logout/',views.LogoutAPIView.as_view(),name='logout'),
    path('delete-account/',views.DeleteUserView.as_view(),name='delete-account'),
    path('change-password/',views.ChangePasswordApiView.as_view(),name='change-password'),
    path('fcm-token/',views.UpdateFCMTokenView.as_view(),name='fcm-token'),
]
