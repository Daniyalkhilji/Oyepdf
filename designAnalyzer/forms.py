from django.contrib.auth.forms import UserCreationForm
# from django.contrib.auth.forms import AuthenticationForm
from .models import CustomUser
from django import forms

# class EmailAuthenticationForm(AuthenticationForm):
#     username = forms.EmailField(widget=forms.EmailInput(attrs={'autofocus': True}))

class CustomUserCreationForm(UserCreationForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1')