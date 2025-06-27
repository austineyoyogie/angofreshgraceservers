from django.db import models
from django.utils import timezone
from django.core import validators
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager)
from rest_framework_simplejwt.tokens import RefreshToken


class QuerySet(models.QuerySet):
    def find_by_id(self, user_id):
        return self.filter(user_id=user_id).values()
        #return self.filter().get(id=user_id)

    def find_by_email(self, email):
        return self.filter(email=email).first()

    def find_if_exists(self, email):
        return self.filter(email=email).exists()


class UserQuerySet(models.Manager):
    def get_queryset(self):
        return QuerySet(self.model, using=self._db)


class UserManager(BaseUserManager, ):
    def _create_user(self, email, password, is_staff, is_superuser, **extra_fields):
        time = timezone.now()
        email = self.normalize_email(email)
        user = self.model(email=email, is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, created_at=time, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        return self._create_user(email, password, False, False, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True, **extra_fields)


class Users(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_('email address'), unique=True, db_index=True,
                              help_text=_('Required. a valid email address for verification '),
                              validators=[validators.RegexValidator(r'^[A-Za-z0-9._@]+$',
                                                                    _('Enter a valid email address. '
                                                                      'This value may contain only letters, numbers @ ' 
                                                                      'and ._ characters.'), 'invalid'), ],
                              error_messages={
                                  'unique': _("A user with that email already exists."),
                              })

    first_name = models.CharField(_('first name'), max_length=45, blank=True,
                                  help_text=_('Required. a valid first name'),
                                  validators=[validators.RegexValidator(r'^[A-Za-z]+$',
                                                                _('Required a valid name characters. '),
                                                                'invalid'), ],
                                  error_messages={
                                      '': _("Required. a valid characters."),
                                  })

    last_name = models.CharField(_('last name'), max_length=45, blank=True,
                                 help_text=_('Required. a valid last name'),
                                 validators=[validators.RegexValidator(r'^[A-Za-z]+$',
                                                               _('Required. a valid name characters. '),
                                                               'invalid'), ],
                                 error_messages={
                                     '': _("Required. a valid characters."),
                                 })

    telephone = models.CharField(_('telephone'), max_length=45, null=False,
                                 help_text=_('Required. a valid mobile number for verification '),
                                 validators=[validators.RegexValidator(r'^[0-9-._ ]+$',
                                                                   _('Enter a valid mobile number. '
                                                                     'This value may contain only numbers '),
                                                                   'invalid'), ],
                                 error_messages={
                                         'unique': _("A user with that mobile number already exists."),
                                     })

    token = models.CharField(_('activate token'), max_length=255)

    is_verified = models.BooleanField(_('verified status'), default=False,
                                      help_text=_('Designates whether this user should be allow to have access.')
                                      )

    is_active = models.BooleanField(_('active statue'), default=False,
                                    help_text=_('Designates whether this user should be treated as '
                                                'active. Deactivate this instead of deleting accounts.'))

    is_using_mfa = models.BooleanField(_('is using mfg'), default=False,
                                       help_text=_('Designates whether this user account access code.')
                                       )

    is_enabled = models.BooleanField(_('is enabled'), default=False,
                                     help_text=_('Designates whether this user account is enabled.')
                                     )

    is_not_locked = models.BooleanField(_('is not locked'), default=False,
                                        help_text=_('Designates whether this user account is locked.')
                                        )

    is_moderator = models.BooleanField(_('moderator status'), default=False,
                                       help_text=_('Designates whether this user should be treated as moderator.')
                                       )

    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin panel. '))

    is_superuser = models.BooleanField(_('superuser status'), default=True,
                                       help_text=_('Designates that this user has all permissions without '
                                                   'explicitly assigning them.'))

    last_login = models.DateTimeField(_('last login'), auto_now=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    deleted_at = models.DateTimeField(_('deleted at'), auto_now=True)

    objects = UserManager()
    obj_query = UserQuerySet()

    USERNAME_FIELD = 'email'

    class Meta:
        verbose_name = _('User Register')
        verbose_name_plural = _('User Registers')

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    # def formatted_date(self):
    #     return self.created_at.strftime('%B %d, %Y at %I:%M %p')