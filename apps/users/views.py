# Create your views here.
from captcha.helpers import captcha_image_url
from captcha.models import CaptchaStore
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from rest_framework import permissions, status, viewsets
from rest_framework.mixins import CreateModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.serializers import jwt_encode_handler, jwt_payload_handler
from users.serializers import UserDetailSerializer, UserRegisterSerializer, UserUpdateSerializer

User = get_user_model()


class PictureCodeView(APIView):
    """
    图片验证码
    """

    throttle_classes = (UserRateThrottle, AnonRateThrottle)

    def get(self, request, format=None):
        response_data = dict()
        response_data["cptch_key"] = CaptchaStore.generate_key()
        response_data["cptch_image"] = captcha_image_url(response_data["cptch_key"])
        return Response(response_data, status=status.HTTP_200_OK, content_type="application/json")


class UserViewset(CreateModelMixin, UpdateModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    用户
    """

    model = User
    queryset = User.objects.all()  # 这里只是定义了SQL语句的写法，并不会真的进行查询，只有当遍历对应数据时才会进行真正的查询
    authentication_classes = (JSONWebTokenAuthentication,)  # 访问该视图需要验证身份信息，将使用这些类

    def get_serializer_class(self):
        if self.action == "create":
            return UserRegisterSerializer
        elif self.action == "update":
            return UserUpdateSerializer

        return UserDetailSerializer

    # permission_classes = (permissions.IsAuthenticated, )
    def get_permissions(self):
        if self.action in ["update", "retrieve"]:
            return [permissions.IsAuthenticated]

        return []

    @method_decorator(login_required(login_url="/"))
    def retrieve(self, request, *args, **kwargs):
        print("---request.data---")
        print(request.data)
        print("----request.user---")
        print(request.user)
        return Response(self.get_serializer_class()(self.get_object()).data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)  # type: UserRegisterSerializer
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  # 注册成功，将SQL记录插入语句提交到数据库执行
        re_dict = serializer.data
        payload = jwt_payload_handler(user)
        re_dict["jwt_token"] = jwt_encode_handler(payload)
        headers = self.get_success_headers(serializer.data)
        return Response(re_dict, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.get_object()
        user.birthday = serializer.data.get("birthday")
        user.password = serializer.data.get("password")
        user.save(update_fields=["birthday", "password"])
        return Response(status=status.HTTP_200_OK)

    def get_object(self):
        return self.request.user
