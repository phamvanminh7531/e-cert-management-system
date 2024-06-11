# Create your models here.
from typing import Iterable
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from Crypto.PublicKey import RSA
from django.core.files.base import ContentFile

class CustomAccountManager(BaseUserManager):

    def create_superuser(self, user_code, password, **other_fields):

        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError(
                'Superuser must be assigned to is_staff=True.')
        if other_fields.get('is_superuser') is not True:
            raise ValueError(
                'Superuser must be assigned to is_superuser=True.')

        return self.create_user(user_code, password, **other_fields)

    def create_user(self, user_code, password, **other_fields):
        other_fields.setdefault('is_active', True)
        user = self.model(user_code=user_code, **other_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    user_code = models.CharField(max_length=150, unique=True)
    full_name = models.CharField(max_length=150, blank=True)
    date_of_birth = models.DateField(blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_teacher = models.BooleanField(default=False)
    is_student = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    private_key = models.FileField(blank=True, null=True, upload_to='private_key/')
    public_key = models.TextField( blank=True, null=True)
    objects = CustomAccountManager()

    USERNAME_FIELD = 'user_code'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.full_name
    
    def save(self, *args, **kwargs):
        if not self.pk:
            key_pair = RSA.generate(1024)
            public_key = key_pair.publickey().exportKey('DER').hex()
            private_key = key_pair.exportKey('PEM')
            file_content = ContentFile(private_key)
            self.public_key = public_key
            self.private_key.save(f'{self.user_code}_private_key.pem', file_content, save=False)
        super(User, self).save(*args, **kwargs)