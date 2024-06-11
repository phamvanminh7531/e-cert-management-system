from django.contrib import admin
from .models import CertHeader, Cert

# Register your models here.
admin.site.register(Cert)
admin.site.register(CertHeader)