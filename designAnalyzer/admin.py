from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import CustomUser
from .models import PdfResult

admin.site.register(CustomUser)
admin.site.register(PdfResult)