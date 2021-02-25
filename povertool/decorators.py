from functools import wraps


def jwt_exempt(view_func):
    """
    排除jwt_exempt校验
    :return:
    """

    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)

    wrapped_view.jwt_exempt = True
    return wraps(view_func)(wrapped_view)


def sign_exempt(view_func):
    """
    排除sign校验
    :return:
    """

    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)

    wrapped_view.sign_exempt = True
    return wraps(view_func)(wrapped_view)
