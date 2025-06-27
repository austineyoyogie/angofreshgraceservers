import string

from django.shortcuts import render
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from rest_framework import generics, status, views, permissions
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import exceptions
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.http import HttpResponseRedirect, Http404, HttpResponse
from auth.authentication.models import Users
from auth.authentication.renderers import JSONRender
from auth.authentication.utils import SendUtil, TokenUtil
import jwt
from .serializers import (
    UserRegisterSerializer, UserLoginSerializer,
    UserEmailVerificationSerializer, ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer, LogoutSerializer
)


class UserRegisterAPIView(generics.GenericAPIView):
    serializer_class = UserRegisterSerializer
    renderer_classes = (JSONRender,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user_data = serializer.data
            if user_data:
                user = Users.objects.get(email=user_data['email'])
                token = RefreshToken.for_user(user).access_token
                token = TokenUtil.gen_random_string_token()
                user.token = str(token)
                user.save()

                current_site = get_current_site(request).domain
                relative_link = reverse('authentication:email-verify')
                abs_url = 'http://' + current_site + relative_link + "?token=" + str(token)
                email_body = 'Hi ' + user.first_name + ' Use link below to verify your email \n' + abs_url
                data = {'body': email_body, 'to': user.email, 'subject': 'Verify your email'}
                SendUtil.send_email(data)
            return Response(user_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogInAPIView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    time = timezone.now()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user_data = serializer.data
            if user_data:
                user = Users.objects.get(email=user_data['email'])
                user.last_login = timezone.now()
                user.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserEmailVerification(generics.GenericAPIView):
    serializer_class = UserEmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = Users.objects.get(id=payload['user_id'])
            if user.is_verified is True:
                raise AuthenticationFailed({'errors': 'Account already be activated.'})
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.is_using_mfa = False  # false for now will work on it later
                user.is_enabled = True
                user.is_not_locked = True
                user.is_staff = True
                user.token = ""
                user.save()
            return Response({'email': 'Account successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'errors': 'Account activation expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'errors': 'Invalid response token'}, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = request.data['email']
            try:   # STOP HERE 9/1/24
                exists = Users.obj_query.get_queryset().find_if_exists(email=email)
            except EOFError:
                raise Http404
            if not exists:
                return Response({'success': 'We have sent you a link to your email.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user = Users.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=request).domain
                # Don't send email now because of front end development
                reletive_link = reverse('authentication:password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
                abs_url = 'http://' + current_site + reletive_link
                email_body = 'Hello, \n Use link below to reset your password \n' + abs_url
                data = {'body': email_body, 'to': user.email, 'subject': 'Reset your password'}
                SendUtil.send_email(data)
            return Response({'success': 'We have sent you a link to reset your password.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get_queryset().get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new token.'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_202_ACCEPTED)
        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new token.'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'success': True, 'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        return Response({'error': 'Password reset error.'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializers = self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        serializers.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
