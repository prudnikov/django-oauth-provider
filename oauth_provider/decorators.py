from oauth_provider.utils import OAuthChecking, oauth_error_response

try:
    from functools import wraps, update_wrapper
except ImportError:
    from django.utils.functional import wraps, update_wrapper  # Python 2.3, 2.4 fallback.

def oauth_required(view_func=None, resource_name=None):
    return CheckOAuth(view_func, resource_name)

class CheckOAuth(OAuthChecking):
    """
    Class that checks that the OAuth parameters passes the given test, raising
    an OAuth error otherwise. If the test is passed, the view function
    is invoked.

    We use a class here so that we can define __get__. This way, when a
    CheckOAuth object is used as a method decorator, the view function
    is properly bound to its instance.
    """
    def __init__(self, view_func, resource_name):
        self.view_func = view_func
        self.resource_name = resource_name
        update_wrapper(self, view_func)
        
    def __get__(self, obj, cls=None):
        view_func = self.view_func.__get__(obj, cls)
        return CheckOAuth(view_func, self.resource_name)

    def __call__(self, request, *args, **kwargs):
        error = self.process_oauth_checking(request, *args, **kwargs)
        if error is None:
            return self.view_func(request, *args, **kwargs)
        else:
            oauth_error_response(error)




