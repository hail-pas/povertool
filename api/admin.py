# Register your models here.
from django.contrib import admin

from .models import User, UserInfo


class UserAdmin(admin.ModelAdmin):
    fields = ["nickname", "phone", "password"]


class UserInfoAdmin(admin.ModelAdmin):
    fields = ["__all__"]


admin.site.register(User, UserAdmin)
admin.site.register(UserInfo, UserInfoAdmin)
