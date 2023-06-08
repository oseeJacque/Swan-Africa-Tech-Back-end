from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User

# Register your models here.
"""
class UserModelAdmin(BaseUserAdmin):

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('id', 'email')
    list_filter = ('is_admin', 'type')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),

    )

    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'nom'),
        }),
    )
    search_fields = ('email')
    ordering = ('id', 'email',)
    filter_horizontal = ()
"""
admin.site.register(User)
