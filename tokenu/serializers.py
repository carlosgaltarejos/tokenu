from rest_framework import serializers
from .models import FileToken

class FileTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileToken
        fields = '__all__'
