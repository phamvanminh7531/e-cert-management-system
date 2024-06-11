from django.db import models
from account.models import User

# Create your models here.
class CertHeader(models.Model):
    subject_name = models.CharField(max_length = 50, null = False)
    teacher = models.ForeignKey(User, on_delete = models.CASCADE, blank = False)
    is_signed_all = models.BooleanField(default=False)
    logo_image = models.FileField(upload_to='cert_logo/')

    def __str__(self) -> str:
        return self.subject_name

class Cert(models.Model):
    cert_header = models.ForeignKey(CertHeader, on_delete=models.CASCADE, blank=False)
    cert_data = models.JSONField()
    is_signed = models.BooleanField(default=False)

    def __str__(self) -> str:
        return str(self.id)