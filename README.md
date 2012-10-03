django-oauth-provider
=====================
Fork of https://bitbucket.org/ditto/django-oauth-provider

Date: 25 Sep, 2012

Last revision: https://bitbucket.org/ditto/django-oauth-provider/changeset/7da959e644fdc6b291ec65890d8da2ba8d820d28

Define <OAUTH_AUTHENTICATION_MIDDLEWARE_REQUEST_FILTER_FUNCTION = lambda request: request.path[:5] == "/api/"> to use custom filter.

OAUTH_PROVIDER_TOKEN_DEFAULT_NAME — default name for the OAuth Token.

OAUTH_PROVIDER_AUTHORIZE_VIEW

OAUTH_PROVIDER_CALLBACK_VIEW — when no callback defined and it is not OOB this view will be used for callback. By default it renders ``oauth_provider/callback.html`` with the only ``request_token`` context variable.

OAUTH_PROVIDER_OUT_OF_BAND_CALLBACK_VIEW — when callback is OOB this view will be used. By default it renders ``oauth_provider/oob_callback.html`` with the only ``request_token`` context variable.
