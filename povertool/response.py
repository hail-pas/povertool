import json

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse, HttpResponse

from api.common import AESUtil


class JSONResponse(JsonResponse):
    """
    自定义Response
    JSONRepsonse(code, msg, data)
    """
    def __init__(self, code=200, data=None, msg=None, encoder=DjangoJSONEncoder, safe=False,
                 json_dumps_params=None, **kwargs):
        ret = {
            'code': code,
        }
        if code == 200:
            ret['data'] = data
        else:
            ret['msg'] = msg
        super(JSONResponse, self).__init__(ret, encoder=encoder, safe=safe,
                                           json_dumps_params=json_dumps_params, **kwargs)


class AESJsonResponse(HttpResponse):
    """
    加密响应
    """
    def __init__(self, code=200, data=None, msg=None, *args, **kwargs):
        ret = {
            'code': code,
        }
        if code == 200:
            ret['data'] = data
        else:
            ret['msg'] = msg
        content = json.dumps(ret, cls=DjangoJSONEncoder, ensure_ascii=False, )
        if not settings.DEBUG:
            content = AESUtil(settings.RESPONSE_ENCRYPT_KEY).encrypt_data(content)
        super(AESJsonResponse, self).__init__(content=content, *args,
                                              **kwargs)