# Generated by Django 5.0.6 on 2024-06-11 06:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userprofile', '0002_customuser_token_created_at_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='verification_token',
        ),
    ]
