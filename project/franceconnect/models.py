from django.db import models
from django.utils import timezone


class FranceConnectState(models.Model):
    created_at = models.DateTimeField(default=timezone.now)
    # Length used in call to get_random_string()
    csrf_string = models.CharField(max_length=12, blank=False, null=False)
