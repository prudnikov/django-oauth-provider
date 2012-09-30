from oauth_provider.consts import REQUEST_FILTER_FUNCTION
from oauth_provider.utils import OAuthChecking

class OAuthAuthenticationMiddleware(OAuthChecking):
    def process_request(self, request, *args, **kwargs):

        if not REQUEST_FILTER_FUNCTION(request):
            return None

        return self.process_oauth_checking(request, *args, **kwargs)