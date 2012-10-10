from django import forms

#
#class AuthorizeRequestTokenForm(forms.Form):
#    oauth_token = forms.CharField(widget=forms.HiddenInput)
#    authorize_access = forms.BooleanField(required=False, label='Allow access')
#
#
#
#from django import forms
from django.conf import settings

class AuthorizeRequestTokenForm(forms.Form):
    oauth_token = forms.CharField(widget=forms.HiddenInput)
    client_name = forms.CharField(max_length=50,
        widget=forms.TextInput(attrs={"placeholder":getattr(settings, "OAUTH_PROVIDER_DEFAULT_CLIENT_NAME", ""),"class":"span5"}),
        help_text="Give this client a name, so later you can differentiate them to revoke access",
        required=False)
    authorize_access = forms.BooleanField(required=False, label='Grant access')

