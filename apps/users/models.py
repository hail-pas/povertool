from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.


class UserProfile(AbstractUser):
    name = models.CharField(max_length=30, null=True, verbose_name="真实姓名")
    mobile = models.CharField(max_length=11, verbose_name="手机号", unique=True)
    birthday = models.DateField(verbose_name="出生年月")
    gender = models.CharField(
        max_length=6,
        choices=(("male", "男"), ("female", "女"), ("other", "其他")),
        default="male",
        verbose_name="性别",
    )
    email = models.EmailField(max_length=100, null=True, blank=True, verbose_name="邮箱")

    class Meta:
        verbose_name = "用户"
        verbose_name_plural = "用户列表"

    def __str__(self):
        return self.username
