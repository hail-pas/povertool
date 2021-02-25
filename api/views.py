from django.shortcuts import render

# Create your views here.
from rest_framework.decorators import api_view

from povertool.response import AESJsonResponse


@api_view(['POST'])
# @params_validation({
#     'phone': validate('phone', fun=lambda x: is_phone(x)),
#     'password': str,
# })
def login(request):
    phone = request.POST.get('phone')
    password = request.POST.get('password')
    return AESJsonResponse(code=401, msg='账号和密码不匹配')