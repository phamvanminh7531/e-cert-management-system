from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin
from django.forms import  Textarea
from django.db import models

class UserAdminConfig(UserAdmin):
    model = User
    search_fields = ('user_code', 'full_name',)
    list_filter = ('user_code', 'full_name', 'is_active', 'is_staff', 'is_teacher', 'is_student', 'is_admin')
    list_display = ('user_code', 'full_name', 'is_active', 'is_staff', 'is_teacher', 'is_student', 'is_admin')
    ordering = ('-full_name',)
    fieldsets = (
        (None, {'fields': ('user_code', 'full_name', 'date_of_birth')}),
        ('Permissions', {'fields': ('is_staff', 'is_active','is_teacher', 'is_student', 'is_admin')}),
        ('Password', {'fields': ('password',)}),
        ('Teacher Key Pair', {'fields': ('private_key','public_key', 'public_key_hash')}),
    )
    readonly_fields = ['private_key','public_key', 'public_key_hash']
    formfield_overrides = {
        models.TextField: {'widget': Textarea(attrs={'rows': 20, 'cols': 60})},
    }
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('user_code', 'full_name', 'password1', 'password2', 'is_active', 'is_staff','is_teacher', 'is_student', 'is_admin')}
         ),
    )

admin.site.register(User, UserAdminConfig)