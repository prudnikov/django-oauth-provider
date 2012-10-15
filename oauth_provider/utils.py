from django.utils.translation import ugettext as _
import oauth2 as oauth
from urlparse import urlparse

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest

from consts import MAX_URL_LENGTH, OUT_OF_BAND
from oauth_provider.consts import OAUTH_PARAMETERS_NAMES

OAUTH_REALM_KEY_NAME = getattr(settings, 'OAUTH_REALM_KEY_NAME', '')
OAUTH_SIGNATURE_METHODS = getattr(settings, 'OAUTH_SIGNATURE_METHODS', ['plaintext', 'hmac-sha1'])
OAUTH_BLACKLISTED_HOSTNAMES = getattr(settings, 'OAUTH_BLACKLISTED_HOSTNAMES', [])

def initialize_server_request(request):
    """Shortcut for initialization."""
    # Django converts Authorization header in HTTP_AUTHORIZATION
    # Warning: it doesn't happen in tests but it's useful, do not remove!
    auth_header = {}
    if 'Authorization' in request.META:
        auth_header = {'Authorization': request.META['Authorization']}
    elif 'HTTP_AUTHORIZATION' in request.META:
        auth_header =  {'Authorization': request.META['HTTP_AUTHORIZATION']}
   
    # Don't include extra parameters when request.method is POST and 
    # request.MIME['CONTENT_TYPE'] is "application/x-www-form-urlencoded" 
    # (See http://oauth.net/core/1.0a/#consumer_req_param).
    # But there is an issue with Django's test Client and custom content types
    # so an ugly test is made here, if you find a better solution...
    parameters = {}
    if request.method == "POST" and \
        (request.META.get('CONTENT_TYPE') == "application/x-www-form-urlencoded" \
            or request.META.get('SERVER_NAME') == 'testserver'):
        parameters = dict((k, v.encode('utf-8')) for (k, v) in request.REQUEST.iteritems())

    oauth_request = oauth.Request.from_request(request.method, 
                                              request.build_absolute_uri(request.path), 
                                              headers=auth_header,
                                              parameters=parameters,
                                              query_string=request.META.get('QUERY_STRING', ''))
    if oauth_request:
        oauth_server = oauth.Server()
        if 'plaintext' in OAUTH_SIGNATURE_METHODS:
            oauth_server.add_signature_method(oauth.SignatureMethod_PLAINTEXT())
        if 'hmac-sha1' in OAUTH_SIGNATURE_METHODS:
            oauth_server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())
    else:
        oauth_server = None
    return oauth_server, oauth_request

def oauth_error_response(err=None, status_code=401):
    """Shortcut for sending an error."""
    # send a 401 error

    if isinstance(err, oauth.Error):
        message = err.message.encode('utf-8')
    else:
        message = str(err).encode('utf-8')

    response = HttpResponse(message, mimetype="text/plain")
    response.status_code = status_code
    # return the authenticate header
    header = oauth.build_authenticate_header(realm=OAUTH_REALM_KEY_NAME)
    for k, v in header.iteritems():
        response[k] = v
    return response

def get_oauth_request(request):
    """ Converts a Django request object into an `oauth2.Request` object. """
    headers = {}
    if 'HTTP_AUTHORIZATION' in request.META:
        headers['Authorization'] = request.META['HTTP_AUTHORIZATION']
    return oauth.Request.from_request(request.method, 
                                      request.build_absolute_uri(request.path), 
                                      headers, 
                                      dict((k, v.encode('utf-8')) for (k, v) in request.REQUEST.iteritems()))

def verify_oauth_request(request, oauth_request, consumer, token=None):
    """ Helper function to verify requests. """
    from store import store

    # Check nonce
    if not store.check_nonce(request, oauth_request, oauth_request['oauth_nonce']):
        return False

    # Verify request
    try:
        oauth_server = oauth.Server()
        oauth_server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())
        oauth_server.add_signature_method(oauth.SignatureMethod_PLAINTEXT())

        # Ensure the passed keys and secrets are ascii, or HMAC will complain.
        consumer = oauth.Consumer(consumer.key.encode('ascii', 'ignore'), consumer.secret.encode('ascii', 'ignore'))
        if token is not None:
            token = oauth.Token(token.key.encode('ascii', 'ignore'), token.secret.encode('ascii', 'ignore'))

        oauth_server.verify_request(oauth_request, consumer, token)
    except oauth.Error, err:
        return False

    return True


def require_params(oauth_request, parameters=[]):
    """ Ensures that the request contains all required parameters. """
    params = [
        'oauth_consumer_key',
        'oauth_nonce',
        'oauth_signature',
        'oauth_signature_method',
        'oauth_timestamp'
    ]
    params.extend(parameters)

    missing = list(param for param in params if param not in oauth_request)
    if missing:
        return HttpResponseBadRequest('Missing OAuth parameters: %s' % (', '.join(missing)))

    return None


def check_valid_callback(callback):
    """
    Checks the size and nature of the callback.
    """
    callback_url = urlparse(callback)
    return (callback_url.scheme
            and callback_url.hostname not in OAUTH_BLACKLISTED_HOSTNAMES
            and len(callback) < MAX_URL_LENGTH)


class OAuthChecking(object):
    def process_oauth_checking(self, request, *args, **kwargs):

        if self.is_valid_request(request):
            oauth_request = get_oauth_request(request)
            from store import store, InvalidConsumerError, InvalidTokenError
            # Retrieve consumer
            try:
                consumer = store.get_consumer(request, oauth_request,
                    oauth_request.get_parameter('oauth_consumer_key'))
                consumer.key = str(consumer.key)
                consumer.secret = str(consumer.secret)
            except InvalidConsumerError:
                return oauth.Error(_('Invalid consumer: %s') % oauth_request.get_parameter('oauth_consumer_key'))
#                return oauth_error_response(oauth.Error(_('Invalid consumer: %s') % oauth_request.get_parameter('oauth_consumer_key')))

            # Retrieve access token
            try:
                token = store.get_access_token(request, oauth_request,
                    consumer, oauth_request.get_parameter('oauth_token'))
                token.key = str(token.key)
                token.secret = str(token.secret)
            except InvalidTokenError:
                return oauth.Error(_('Invalid access token: %s') % oauth_request.get_parameter('oauth_token'))
#                return oauth_error_response(oauth.Error(_('Invalid access token: %s') % oauth_request.get_parameter('oauth_token')))

            try:
                parameters = self.validate_token(request, consumer, token)
            except oauth.Error, e:
                return e
#                return oauth_error_response(e)

            if consumer and token:
                request.user = token.user
                request.consumer = consumer
                request.token = token
            return None
        return oauth.Error(_('Invalid request parameters.'))
#        return oauth_error_response(oauth.Error(_('Invalid request parameters.')))

    @staticmethod
    def is_valid_request(request):
        """
        Checks whether the required parameters are either in
        the http-authorization header sent by some clients,
        which is by the way the preferred method according to
        OAuth spec, but otherwise fall back to `GET` and `POST`.
        """
        is_in = lambda l: all((p in l) for p in OAUTH_PARAMETERS_NAMES)
        auth_params = request.META.get("HTTP_AUTHORIZATION", [])
        return is_in(auth_params) or is_in(request.REQUEST)

    @staticmethod
    def validate_token(request, consumer, token):
        oauth_server, oauth_request = initialize_server_request(request)
        return oauth_server.verify_request(oauth_request, consumer, token)