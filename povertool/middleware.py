from urllib.parse import parse_qs, quote

from django.http import QueryDict

from api import apps
from povertool.response import AESJsonResponse


class RequestMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        if request.method == 'PUT':
            request.PUT = QueryDict(request.body).dict()
        elif request.method == 'DELETE':
            request.DELETE = QueryDict(request.body).dict()
        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.
        return response

    def process_view(self, request, view_func, *view_args, **view_kwargs):
        """
        实现某些view
        :param request:
        :param view_func:
        :param view_args:
        :param view_kwargs:
        :return:
        """
        # 可以按app_name 筛选 rest_framework下的app
        app_name = request.resolver_match.app_name
        if app_name in [apps.ApiConfig.name]:
            # 配合装饰
            if getattr(view_func, 'sign_exempt', False):  # FBV
                return
            # rest_framework 的 CBV
            if request.method in getattr(view_func.view_class, 'sign_exempt_methods', []): # CBV
                return
        else:
            return

        params = dict(QueryDict(request.body).dict(), **request.GET.dict())
        timestamp = params.get('timestamp')  # type:str

        if not timestamp or not timestamp.isdigit():
            return AESJsonResponse(code=415, msg='timestamp required')

        # 改写request
        overwrite_request(request)


def overwrite_request(request):
    """
    GET请求， 重写timestamp参数以支持缓存
    :param request:
    :return:
    """
    if request.method == 'GET':
        query_string = request.META['QUERY_STRING']
        qs = parse_qs(query_string)
        qs.pop('timestamp', '')
        qs_list = []
        for k in qs:
            qs_list.append(f'{k}={quote(qs.get(k)[0])}')
        request.META['QUERY_STRING'] = '&'.join(qs_list)
    return request