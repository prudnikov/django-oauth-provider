from django.conf.urls import patterns, include, url
from django.contrib import admin
from oauth_provider.views import protected_resource_example

admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'provider.views.home', name='home'),
    # url(r'^provider/', include('provider.foo.urls')),

    url(r'^oauth/', include('oauth_provider.urls')),
    url(r'^oauth/photo/$', protected_resource_example, name='oauth_example'),

    url(r'^admin/', include(admin.site.urls)),
)
