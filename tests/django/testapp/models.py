from django.conf import settings
from django.db import models


class Profile(models.Model):
    """An application row that a user factory creates with each user."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    display_name = models.CharField(max_length=100)
