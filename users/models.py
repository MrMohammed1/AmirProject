from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, unique=True) 
    otp = models.CharField(max_length=6)  
    expiration_time = models.DateTimeField() 

    def is_expired(self):
        return timezone.now() > self.expiration_time 

