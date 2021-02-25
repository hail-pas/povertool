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
from rest_framework.documentation import include_docs_urls

# schema_view = get_schema_view(
#     openapi.Info(
#         title="API of Povertool",    # 必传
#         default_version='v1',   # 必传
#         description="Povertool接口文档",
#         terms_of_service=settings.SERVER_URL,
#         contact=openapi.Contact(email="yueyueniao@qq.com"),
#         license=openapi.License(name="BSD License"),
#     ),
#     public=True,
#     # permission_classes=(permissions.AllowAny,),   # 权限类
# )

urlpatterns = [
    path("admin/", admin.site.urls),
    url(
        r"^static/(?P<path>.*)$",
        static.serve,
        {"document_root": settings.STATIC_ROOT},
        name="static",
    ),
    path("api-auth/", include("rest_framework.urls")),
    path("api/", include(("api.urls", "api"), namespace="api")),
    url(r"docs/", include_docs_urls(title="API of Povertool")),
]
