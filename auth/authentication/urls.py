from django.urls import path

from auth.authentication.views import (
    UserRegisterAPIView, UserLogInAPIView,
    UserEmailVerification, RequestPasswordResetEmail,
    PasswordResetConfirmTokenCheckAPI, SetNewPasswordAPIView, LogoutAPIView)
from rest_framework_simplejwt.views import (
    TokenRefreshView, TokenBlacklistView
)

app_name = 'auth.authentication'

urlpatterns = [
    path('register', UserRegisterAPIView.as_view(), name='register'),
    path('login', UserLogInAPIView.as_view(), name="login"),
    path('email-verify', UserEmailVerification.as_view(), name="email-verify"),
    path('token/refresh', TokenRefreshView.as_view(), name="token_refresh"),
    path('token/blacklist', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('request-reset-email', RequestPasswordResetEmail.as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>', PasswordResetConfirmTokenCheckAPI.as_view(), name="password-reset-confirm"),
    path('request-reset-complete', SetNewPasswordAPIView.as_view(), name="request-reset-complete"),
    path('logout', LogoutAPIView.as_view(), name="logout"),
    # path('details/', UserRegisterDetails.as_view(), name='details'),
]

# url(r'^user-activation/(?P<id>[\w\.-]+)/', views.UserActivation.as_view()),