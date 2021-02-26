import datetime
import re

from rest_framework import serializers

from api import models
from povertool.common import Password


class UserSerializer(serializers.ModelSerializer):
    # id = serializers.IntegerField(read_only=True)
    phone = serializers.CharField(
        label="手机号码",
        max_length=20,
        min_length=11,
        required=True,
        error_messages={"required": "手机号码必填", "min_length": "手机号码格式错误", "max_length": "手机号码格式错误"},
    )
    registered_days = serializers.SerializerMethodField()

    def validate_phone(self, phone):
        """
        验证手机号码的函数
        :param phone:
        :return:
        """

        # 判断用户是否已经注册
        if models.User.objects.filter(phone=phone).count():
            raise serializers.ValidationError("该用户已经存在")

        # 正则判断手机号码格式
        if not re.match(r"^1[3-9]\d{9}$", phone):
            raise serializers.ValidationError("手机号码格式错误")

        return phone

    def get_registered_days(self, obj: models.User):
        """
        动态计算注册多少时间
        :param obj:
        :return:
        """
        return obj.created_at - datetime.datetime.now()

    def validate(self, attrs):
        """
        操作校验数据集
        :param attrs:
        :return:
        """
        # attrs['password'] = Password.get_password_hash(attrs["password"])
        return attrs

    def create(self, validated_data):
        return models.User.objects.create(
            ip=self.context["ip"], password=self.context["password"], **validated_data
        )

    # def update(self, instance, validated_data):
    #     pass

    class Meta:
        model = models.User
        exclude = ["id", "password", "ip"]


class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserInfo
        fields = "__all__"
