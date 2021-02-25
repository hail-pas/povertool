import datetime

from rest_framework import serializers

from api import models


class UserSerializer(serializers.ModelSerializer):
    # id = serializers.IntegerField(read_only=True)
    registered_days = serializers.SerializerMethodField()

    def get_registered_days(self, obj: models.User):
        return obj.created_at - datetime.datetime.now()

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
