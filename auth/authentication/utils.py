from django.core.mail import EmailMessage
import string
import secrets
import random


class SendUtil:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to']])
        email.send()


class TokenUtil:
    @staticmethod
    def gen_random_string_token(token):
        token_str = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_letters +
                                           string.ascii_lowercase + string.octdigits +
                                           string.hexdigits + string.digits) for i in range(token))
        return token_str
