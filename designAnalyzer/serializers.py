from rest_framework import serializers
from .models import PdfResult

class pdfParserSerializer(serializers.ModelSerializer):
    class Meta:
        model = PdfResult
        fields = '__all__'
