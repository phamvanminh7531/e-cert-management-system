# Generated by Django 4.0.5 on 2024-06-23 07:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cert', '0003_remove_cert_student'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certheader',
            name='logo_image',
            field=models.FileField(blank=True, null=True, upload_to='cert_logo/'),
        ),
    ]
