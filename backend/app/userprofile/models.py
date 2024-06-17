from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class CustomUser(AbstractUser):
    email_verified=models.BooleanField(default=False)
    token_created_at = models.DateTimeField(null=True, blank=True)
    token_expiry_time = models.DateTimeField(null=True, blank=True)

    def is_token_valid(self):
        if self.token_created_at and self.token_expiry_time:
            return timezone.now() < self.token_expiry_time
        return False

    
# Create your models here.


    