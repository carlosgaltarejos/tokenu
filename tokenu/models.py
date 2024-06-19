from django.db import models

class FileToken(models.Model):
    file = models.FileField(upload_to='uploads/')
    ethereum_token_address = models.CharField(max_length=42, blank=True, null=True)
    polygon_token_address = models.CharField(max_length=42, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
