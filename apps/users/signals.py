from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

User = get_user_model()


@receiver(post_save, sender=User)
def create_user(sender, instance=None, created=False, **kwargs):
    update_fields = kwargs.get("update_fields") or []
    if created or "password" in update_fields:
        password = instance.password
        instance.set_password(password)
        instance.save()
