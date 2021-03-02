from django.http import QueryDict


class RequestMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        if request.method == "PUT":
            request.PUT = QueryDict(request.body).dict()
        elif request.method == "DELETE":
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
        pass
