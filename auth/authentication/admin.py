from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from auth.authentication.models import Users
from django.contrib.auth.admin import UserAdmin


class UserAdminConfig(UserAdmin):
    model = Users

    # ADMIN EDITABLE
    fieldsets = (
        # None editable fields
        # (None, {'field': ('token', 'password')}),
        (_('Personal info'), {'fields': ('email', 'first_name', 'last_name', 'telephone')}),
        (_('Permissions'), {'fields': ('is_verified', 'is_using_mfa', 'is_enabled', 'is_not_locked',
                                       'is_moderator', 'is_staff', 'is_active', 'is_superuser',
                                       'groups', 'user_permissions')}),
        # None editable fields
        # (_('Important dates'), {'fields': ('last_login', 'updated_at', 'deleted_at')}),
    )
    # CREATE SUPERUSER
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    # ADMIN VIEWS
    list_display = ('id', 'email', 'first_name', 'last_name', 'telephone', 'token',
                    'is_verified', 'is_active', 'is_using_mfa', 'is_enabled',
                    'is_not_locked', 'is_moderator', 'is_staff', 'is_superuser',
                    'last_login', 'created_at', 'updated_at', 'deleted_at')

    # ADMIN KEYWORD SEARCHABLE FIELDS
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'groups')
    search_fields = ('email', 'first_name', 'last_name', 'telephone')
    ordering = ('last_name',)
    filter_horizontal = ('groups', 'user_permissions',)


admin.site.register(Users, UserAdminConfig)