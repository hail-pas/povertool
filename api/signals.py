from django.db.models.signals import post_save
from django.dispatch import receiver

from api import models


@receiver(post_save, sender=models.User)
def user_save(sender, **kwargs):
    """
    用户信号
    :param sender:
    :param kwargs:
    :return:
    """
    user = kwargs.get("instance")  # type:models.User
    update_fields = kwargs.get("update_fields") or []
    created = kwargs.get("created")
    if created:
        pass

    if "phone" in update_fields:
        pass
