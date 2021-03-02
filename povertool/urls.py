"""povertool URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path("", views.home, name="home")
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path("", Home.as_view(), name="home")
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path("blog/", include("blog.urls"))
"""
from django.conf import settings
from django.conf.urls import url
from django.contrib import admin
from django.urls import include, path
from django.views import static
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework.routers import DefaultRouter
from rest_framework_jwt.views import obtain_jwt_token
from users.views import PictureCodeView, UserViewset

schema_view = get_schema_view(
    openapi.Info(
        title="Povertool API",
        default_version="v1.0.0",
        description="API doc of Povertool",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="hypofiasco@gmail.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

router = DefaultRouter()
router.register(r"users", UserViewset, "users")

urlpatterns = [
    url(r"^", include(router.urls)),  # 将调用注册到router的各个ViewSet的as_view()方法，得到最终的URL映射配置
    path("admin/", admin.site.urls),
    # 静态文件
    url(
        r"^static/(?P<path>.*)$",
        static.serve,
        {"document_root": settings.STATIC_ROOT},
        name="static",
    ),
    path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    # 自动生成的API说明文档
    # 配置drf-yasg路由
    path("docs/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    # url(r"docs/", include_docs_urls(title="API of Povertool")),
    # 验证码
    path("captcha/", include("captcha.urls")),
    url(r"picturecode/", PictureCodeView.as_view(), name="picturecode"),
    url(r"login/", obtain_jwt_token),  # jwt的认证接口（较之drf自带的认证模式，占用的服务器端资源更少，安全性更高）
]
