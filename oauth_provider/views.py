import httplib
from urllib import urlencode

import oauth2 as oauth
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import ugettext as _
from django.core.urlresolvers import get_callable
from django.views.generic.simple import direct_to_template

from decorators import oauth_required
from forms import AuthorizeRequestTokenForm
from store import store, InvalidConsumerError, InvalidTokenError
from utils import verify_oauth_request, get_oauth_request, require_params, oauth_error_response
from consts import OUT_OF_BAND

OAUTH_PROVIDER_AUTHORIZE_VIEW = 'OAUTH_PROVIDER_AUTHORIZE_VIEW'
OAUTH_PROVIDER_CALLBACK_VIEW = 'OAUTH_PROVIDER_CALLBACK_VIEW'
OAUTH_PROVIDER_OUT_OF_BAND_CALLBACK_VIEW = 'OAUTH_PROVIDER_OUT_OF_BAND_CALLBACK_VIEW'
INVALID_PARAMS_RESPONSE = oauth_error_response(oauth.Error(
                                            _('Invalid request parameters.')))

@csrf_exempt
def request_token(request):
    oauth_request = get_oauth_request(request)
    if oauth_request is None:
        return INVALID_PARAMS_RESPONSE

    missing_params = require_params(oauth_request, ('oauth_callback',))
    if missing_params is not None:
        return missing_params

    try:
        consumer = store.get_consumer(request, oauth_request, oauth_request['oauth_consumer_key'])
    except InvalidConsumerError:
        return oauth_error_response('Invalid Consumer.', status_code=httplib.BAD_REQUEST)

    if not verify_oauth_request(request, oauth_request, consumer):
        return oauth_error_response('Could not verify OAuth request.', status_code=httplib.BAD_REQUEST)

    try:
        request_token = store.create_request_token(request, oauth_request, consumer, oauth_request['oauth_callback'])
    except oauth.Error, err:
        return oauth_error_response(err)

    ret = urlencode({
        'oauth_token': request_token.key,
        'oauth_token_secret': request_token.secret,
        'oauth_callback_confirmed': 'true'
    })
    return HttpResponse(ret, content_type='application/x-www-form-urlencoded')


@login_required
def user_authorization(request, form_class=AuthorizeRequestTokenForm):
    if 'oauth_token' not in request.REQUEST:
        return oauth_error_response('No request token specified.', status_code=httplib.BAD_REQUEST)

    oauth_request = get_oauth_request(request)

    try:
        request_token = store.get_request_token(request, oauth_request, request.REQUEST['oauth_token'])
    except InvalidTokenError:
        return oauth_error_response('Invalid request token.', status_code=httplib.BAD_REQUEST)

    consumer = store.get_consumer_for_request_token(request, oauth_request, request_token)

    if request.method == 'POST':
        form = form_class(request.POST)
        if request.session.get('oauth', '') == request_token.key and form.is_valid():
            request.session['oauth'] = ''
            if form.cleaned_data['authorize_access']:
                request_token.name = form.cleaned_data.get("client_name", getattr(settings, "OAUTH_PROVIDER_TOKEN_DEFAULT_NAME", "Unnamed"))
                request_token = store.authorize_request_token(request, oauth_request, request_token)
                args = { 'oauth_token': request_token.key }
            else:
                args = { 'error': _('Access not granted by user.') }

            if request_token.callback is not None and request_token.callback != OUT_OF_BAND:
                response = HttpResponseRedirect('%s&%s' % (request_token.get_callback_url(), urlencode(args)))
            else:
                # try to get custom callback view
                if request_token.callback == OUT_OF_BAND:
                    callback_view_str = getattr(settings, OAUTH_PROVIDER_OUT_OF_BAND_CALLBACK_VIEW,
                        'oauth_provider.views.fake_out_of_band_callback_view')
                else:
                    # try to get custom callback view
                    callback_view_str = getattr(settings, OAUTH_PROVIDER_CALLBACK_VIEW,
                        'oauth_provider.views.fake_callback_view')

                try:
                    callback_view = get_callable(callback_view_str)
                except AttributeError:
                    raise Exception, "%s view doesn't exist." % callback_view_str
                response = callback_view(request, request_token, **args)
        else:
            response = oauth_error_response(oauth.Error(_('Action not allowed.')))
    else:
        # try to get custom authorize view
        authorize_view_str = getattr(settings, OAUTH_PROVIDER_AUTHORIZE_VIEW,
                                    'oauth_provider.views.default_authorize_view')
        try:
            authorize_view = get_callable(authorize_view_str)
        except AttributeError:
            raise Exception, "%s view doesn't exist." % authorize_view_str
        params = oauth_request.get_normalized_parameters()
        # set the oauth flag
        request.session['oauth'] = request_token.key
        response = authorize_view(request, request_token, request_token.get_callback_url(), params)
        
    return response


@csrf_exempt
def access_token(request):
    oauth_request = get_oauth_request(request)
    if oauth_request is None:
        return INVALID_PARAMS_RESPONSE

    missing_params = require_params(oauth_request, ('oauth_token', 'oauth_verifier'))
    if missing_params is not None:
        return missing_params

    try:
        request_token = store.get_request_token(request, oauth_request, oauth_request['oauth_token'])
    except InvalidTokenError:
        return oauth_error_response('Invalid request token.', status_code=httplib.BAD_REQUEST)
    try:
        consumer = store.get_consumer(request, oauth_request, oauth_request['oauth_consumer_key'])
    except InvalidConsumerError:
        return oauth_error_response('Invalid consumer.', status_code=httplib.BAD_REQUEST)

    if not verify_oauth_request(request, oauth_request, consumer, request_token):
        return oauth_error_response('Could not verify OAuth request.', status_code=httplib.BAD_REQUEST)

    if oauth_request.get('oauth_verifier', None) != request_token.verifier:
        return oauth_error_response('Invalid OAuth verifier.', status_code=httplib.BAD_REQUEST)

    if not request_token.is_approved:
        return oauth_error_response('Request Token not approved by the user.', status_code=httplib.BAD_REQUEST)

    access_token = store.create_access_token(request, oauth_request, consumer, request_token)

    ret = urlencode({
        'oauth_token': access_token.key,
        'oauth_token_secret': access_token.secret
    })
    return HttpResponse(ret, content_type='application/x-www-form-urlencoded')

@oauth_required
def protected_resource_example(request):
    """
    Test view for accessing a Protected Resource.
    """
    return HttpResponse('Protected Resource access!')

@login_required
def fake_authorize_view(request, token, callback, params):
    """
    Fake view for tests. It must return an ``HttpResponse``.
    
    You need to define your own in ``settings.OAUTH_PROVIDER_AUTHORIZE_VIEW``.
    """
    return HttpResponse('Fake authorize view for %s with params: %s.' % (token.consumer.name, params))

@login_required
def default_authorize_view(request, token, callback, params, form_class=AuthorizeRequestTokenForm):
    return direct_to_template(request, 'oauth_provider/authorize.html', {
        'form': form_class(initial={'oauth_token': token.key}),
        'consumer': token.consumer,
    })

def default_callback_view(request, token, **kwargs):
    return direct_to_template(request, 'oauth_provider/callback.html', {
        'token': token,
    })

def fake_callback_view(request, token, **args):
    """
    Fake view for tests. It must return an ``HttpResponse``.
    
    You can define your own in ``settings.OAUTH_PROVIDER_CALLBACK_VIEW``.
    """
    return HttpResponse('Fake callback view.')


def default_out_of_bands_callback_view(request, token, **kwargs):
    return direct_to_template(request, 'oauth_provider/oob_callback.html', {
        'token': token,
    })

def fake_out_of_band_callback_view(request, token, **kwargs):
    return HttpResponse('Fake out of bands callback view.')