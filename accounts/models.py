from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.
class User(AbstractUser):
    first_name    = models.CharField(max_length=30, blank=True)
    last_name     = models.CharField(max_length=30, blank=True)
    email         = models.EmailField(unique=True)
    phone_number  = models.CharField(max_length=15, unique=True)
    otp 		  = models.CharField(max_length=6, null=True, blank=True)
    created_time  = models.DateTimeField(auto_now_add=True)
    utimestamp 	  = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username