from django.db import models
from django.contrib.auth.models import AbstractUser
from django import forms
from django.utils import timezone

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)
    otp = models.CharField(max_length=6, blank=True, null=True)  # Add the otp field
    def __str__(self):
        return self.username


class PdfResult(models.Model):
    file_name = models.CharField(max_length=255)
    status = models.CharField(max_length=20)
    result = models.JSONField()
    date_created = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE) 
    def __str__(self):
        return self.file_name
