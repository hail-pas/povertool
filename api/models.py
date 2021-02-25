from django.db import models

# Create your models here.


class User(models.Model):
    nickname = models.CharField(max_length=200, help_text="昵称", verbose_name="昵称")
    avatar = models.URLField(
        help_text="用户头像", verbose_name="用户头像", default="http://static.povertool.cn/avatar.png"
    )
    province = models.CharField(
        default="", max_length=50, help_text="省", verbose_name="省", blank=True
    )
    city = models.CharField(default="", max_length=20, help_text="市", verbose_name="市", blank=True)
    district = models.CharField(
        default="", max_length=20, help_text="区县", verbose_name="区县", blank=True
    )
    phone = models.CharField(
        help_text="手机号", verbose_name="手机号", db_index=True, max_length=20, unique=True
    )
    password = models.CharField(max_length=200)
    ip = models.GenericIPAddressField()
    created_at = models.DateTimeField(auto_now_add=True, help_text="创建时间", verbose_name="创建时间")
    updated_at = models.DateTimeField(auto_now=True, help_text="更新时间", verbose_name="更新时间")

    def __str__(self):
        return f"{self.pk}#{self.phone}#{self.nickname}"

    class Meta:
        unique_together = [("phone", "nickname")]
        index_together = [("phone", "nickname")]
        ordering = ["-id"]
        verbose_name = "用户"
        verbose_name_plural = "用户列表"


class UserInfo(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(default="", help_text="真实姓名", verbose_name="真实姓名", max_length=50)
    birthday = models.DateField(help_text="出生日期", verbose_name="出生日期")
    sex = models.CharField(max_length=2)
    address = models.CharField(max_length=50)
    nation = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True, help_text="创建时间", verbose_name="创建时间")
    updated_at = models.DateTimeField(auto_now=True, help_text="更新时间", verbose_name="更新时间")

    def __str__(self):
        return f"{self.pk}#{self.name}"

    class Meta:
        verbose_name = "用户资料"
        verbose_name_plural = "用户资料列表"
