from datetime import datetime
from django.db import models
from django.contrib import auth
from django.utils import timezone
from rest_framework import serializers
from rest_framework import exceptions
from rest_framework import generics, status
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import \
    OutstandingToken, BlacklistedToken
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from auth.authentication.models import Users


class UserRegisterSerializer(serializers.ModelSerializer):
    password = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        model = Users
        fields = ['email', 'first_name', 'last_name', 'telephone',  'is_verified', 'is_active', 'password',
                  'is_using_mfa', 'is_enabled', 'is_not_locked', 'is_moderator', 'is_staff', ]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        email = attrs.get('email', '')
        if not email:
            raise serializers.ValidationError('The email should not contain: %s' % email)
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.is_active = False
        instance.is_superuser = False
        instance.save()
        return instance


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=45, min_length=6)
    password = serializers.CharField(max_length=255, min_length=6, write_only=True)
    token = serializers.SerializerMethodField()

    class Meta:
        model = Users
        fields = ['email', 'password', 'token']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed({'error': 'Invalid user credentials.'})
        if not user.is_verified:
            raise AuthenticationFailed({'error': 'Invalid user account, or you have not verified your account?.'})
        if not user.is_active:
            raise AuthenticationFailed({'error': 'Invalid user account, or your account is not inactive?.'})
        if not user.is_using_mfa:
            raise AuthenticationFailed({'error': 'Two factor authentication?.'})
        if not user.is_enabled:
            raise AuthenticationFailed({'error': 'Account is not enabled?.'})
        if not user.is_not_locked:
            raise AuthenticationFailed({'error': 'Account is locked?.'})
        return super().validate(attrs)

    @staticmethod
    def get_token(obj):
        user = Users.objects.get(email=obj['email'])
        return {
            'fullName': user.get_full_name(),
            'access': user.tokens()['access'],
            'refresh': user.tokens()['refresh']
        }


class UserEmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = Users
        fields = ['email']


class ResetPasswordEmailRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        model = Users
        fields = ['email']


class SetNewPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=2, write_only=True)
    uidb64 = serializers.CharField(min_length=2, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get_queryset().get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset linked is invalid', status.HTTP_401_UNAUTHORIZED)
            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            raise AuthenticationFailed('The reset linked is invalid', status.HTTP_401_UNAUTHORIZED)
        return super().validate(attrs)


class LogoutSerializer(serializers.ModelSerializer):
    refresh = serializers.CharField()

    default_error_messages = {
       'bad_token': 'Token is expired or invalid'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
            BlacklistedToken.objects.filter(token__expires_at__lt=timezone.now()).delete()
            OutstandingToken.objects.filter(expires_at__lt=timezone.now()).delete()
        except TokenError:
            self.fail('Token is expired or invalid')
