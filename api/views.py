import datetime

from django.conf import settings
from django.db.models import Q
from django.shortcuts import get_object_or_404

# Create your views here.
from django.utils.decorators import method_decorator
from rest_framework.decorators import api_view
from rest_framework.views import APIView

from api import models, serializers
from povertool.common import Jwt, Password, datetime_now, get_client_ip
from povertool.decorators import jwt_exempt, sign_exempt
from povertool.responses import AESJsonResponse, PageNumberSizePagination


@sign_exempt
@jwt_exempt
@api_view(["POST"])
def register(request):
    data = request.POST.dict()
    phone = request.POST.get("phone")
    password = request.POST.get("password")
    us = serializers.UserSerializer(
        data=data,
        context=dict(password=Password.get_password_hash(password), ip=get_client_ip(request),),
    )
    if us.is_valid():
        user = us.save()
        return AESJsonResponse()
    return AESJsonResponse(code=433, msg=us.errors)


@sign_exempt
@jwt_exempt
@api_view(["POST"])
def login(request):
    phone = request.POST.get("phone")
    password = request.POST.get("password")
    user = get_object_or_404(models.User, phone=phone)
    print("password: ", password)
    print("u_pa:", user.password)
    if not Password.verify_password(password, user.password):
        return AESJsonResponse(code=401, msg="账号和密码不匹配")
    token = Jwt(settings.JWT_ENCRYPT_KEY).get_jwt(payload=dict(user_id=user.pk))
    return AESJsonResponse(
        data=dict(access_token=token, user_info=serializers.UserSerializer(user).data)
    )


# APIView的dispatch函数实现分发到不同的方法
# 等价于 @api_view(["GET", "PUT"]): if request.method == "GET": pass; if request.method == "PUT": pass;
#
class UserInfoView(APIView):
    # 单独指定 授权认证类 和 权限
    # authentication_classes = (authentication.TokenAuthentication,)
    # permission_classes = (permissions.IsAdminUser,)
    # @method_decorator()  传入装饰器，装饰器不能直接装饰视图函数
    jwt_exempt_methods = ["GET"]
    sign_exempt_methods = ["GET", "put"]

    def get(self, request):
        # jwt校验中间件
        qs = models.UserInfo.objects.filter(user=request.user)
        # 分页
        pg = PageNumberSizePagination()
        qs = pg.paginate_queryset(qs, request)
        data = serializers.UserInfoSerializer(qs, many=True).data
        return AESJsonResponse(data=data)

    def put(self, request):
        user = request.user  # type:models.User
        user_infos = user.infos
        birthday = datetime.datetime.strptime(request.GET.get("birthday"), "%Y-%m-%d %H:%M:%S")
        for user_info in user_infos:
            user_info.birthday = birthday
            user_info.save(update_fields=["birthday", "updated_at"])
        return AESJsonResponse()


@sign_exempt
@jwt_exempt
@api_view(["GET"])
def check_user(request, user_id):
    # url传递参数
    user = get_object_or_404(models.User, pk=user_id)
    return AESJsonResponse(data=serializers.UserSerializer(user).data)
