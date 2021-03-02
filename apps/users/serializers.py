from captcha.models import CaptchaStore
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

User = get_user_model()


class UserDetailSerializer(serializers.ModelSerializer):
    """
    用户详情序列化类
    """

    class Meta:
        model = User
        fields = ("username", "name", "mobile", "gender", "birthday", "email")


# Serializer类的所有属性和方法都被作为检验条件，必须全部都符合要求
class UserRegisterSerializer(serializers.ModelSerializer):
    # picture_code = serializers.CharField(required=True, allow_blank=False, write_only=True, max_length=4, min_length=4,
    #                                      label="验证码",
    #                                      error_messages={
    #                                          "blank": "请输入验证码",
    #                                          "required": "请输入验证码",
    #                                          "max_length": "验证码格式错误",
    #                                          "min_length": "验证码格式错误"
    #                                      },
    #                                      help_text="验证码")
    # picture_key = serializers.CharField(required=True, write_only=True, max_length=40, min_length=40, label="验证码令牌",
    #                                     error_messages={
    #                                         "blank": "请传输验证码Key",
    #                                         "required": "请传输验证码Key",
    #                                         "max_length": "验证码Key格式错误",
    #                                         "min_length": "验证码Key格式错误"
    #                                     },
    #                                     help_text="验证码令牌")
    mobile = serializers.CharField(
        label="手机号",
        max_length=11,
        min_length=11,
        required=True,
        allow_blank=False,
        error_messages={
            "blank": "请输入手机号",
            "required": "请输入手机号",
            "max_length": "手机号格式错误",
            "min_length": "手机号格式错误",
        },
        help_text="输入手机号",
        validators=[UniqueValidator(queryset=User.objects.all(), message="手机号已被注册")],
    )
    birthday = serializers.DateField(
        label="出生日期",
        required=True,
        error_messages={"blank": "请输入出生日期", "required": "请输入出生日期",},
        help_text="输入出生日期",
    )
    # 除了一般的格式检查外，用户名还需要查询全库是否存在重复
    username = serializers.CharField(
        label="用户名",
        help_text="用户名",
        required=True,
        allow_blank=False,
        validators=[UniqueValidator(queryset=User.objects.all(), message="用户已经存在")],
    )
    name = serializers.CharField(label="用户名", help_text="用户名", required=True, allow_blank=False)
    gender = serializers.ChoiceField(
        choices=(("male", "男"), ("female", "女"), ("other", "其他")), required=True
    )

    password = serializers.CharField(
        style={"input_type": "password"}, help_text="密码", label="密码", write_only=True,
    )

    # def validate(self, attrs):
    #     picture_code = attrs["picture_code"]
    #     picture_key = attrs["picture_key"]
    #     try:
    #         if captcha_record := CaptchaStore.objects.get(hashkey=picture_key):
    #             expiration = captcha_record.expiration
    #             response = captcha_record.response
    #             captcha_record.delete()
    #             if timezone.now() > expiration:
    #                 raise serializers.ValidationError("验证码过期")
    #             if response != picture_code.lower():
    #                 raise serializers.ValidationError("验证码错误")
    #     except CaptchaStore.DoesNotExist:
    #         raise serializers.ValidationError("验证码Key错误")
    #     # 数据检查结束，这些属性是不写入到数据表的，必须删掉
    #     del attrs["picture_code"]
    #     del attrs["picture_key"]
    #     return attrs

    class Meta:
        model = User
        fields = ("username", "name", "gender", "mobile", "password", "birthday")


class UserUpdateSerializer(serializers.ModelSerializer):
    birthday = serializers.DateField(
        label="出生日期",
        required=True,
        error_messages={"blank": "请输入出生日期", "required": "请输入出生日期",},
        help_text="输入出生日期",
    )
    # 除了一般的格式检查外，用户名还需要查询全库是否存在重复
    password = serializers.CharField(
        style={"input_type": "password"}, help_text="密码", label="密码", write_only=True,
    )

    class Meta:
        model = User
        fields = ("password", "birthday")
