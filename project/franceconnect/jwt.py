from django.conf import settings
from django.utils import timezone


def jwt_payload_handler(user):
    """Custom payload handler"""
    return {"user_id": user.pk, "exp": timezone.now() + settings.JWT_EXPIRATION_DELTA}
