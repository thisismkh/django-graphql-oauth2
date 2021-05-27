from functools import wraps

from graphql.execution.execute import GraphQLResolveInfo

from provider import constants


def context(fun):
    def decorator(func):
        def wrapper(*args, **kwargs):
            info = next(
                arg for arg in args
                if isinstance(arg, GraphQLResolveInfo)
            )
            return func(info.context, *args, **kwargs)
        return wrapper
    return decorator


def user_passes_test(test_func, exc=constants.ERROR_HANDLER('unauthorized')):
    def decorator(f):
        @wraps(f)
        @context(f)
        def wrapper(context, *args, **kwargs):
            if test_func(context.user):
                return f(*args, **kwargs)
            raise exc
        return wrapper
    return decorator


login_required = user_passes_test(lambda u: u.is_authenticated)
staff_member_required = user_passes_test(lambda u: u.is_staff)
superuser_required = user_passes_test(lambda u: u.is_superuser)