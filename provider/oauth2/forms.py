from six import string_types
from django import forms
from django.contrib.auth import authenticate
from django.conf import settings
from django.utils.translation import ugettext as _
from django.utils import timezone
from graphql import GraphQLError
from provider.constants import RESPONSE_TYPE_CHOICES, SCOPES, PUBLIC, ERROR_HANDLER
from provider.forms import OAuthForm, OAuthValidationError
from provider.utils import now
from provider.oauth2.models import Client, Grant, RefreshToken, Scope


DEFAULT_SCOPE = getattr(settings, 'OAUTH2_DEFAULT_SCOPE', 'read')


class ClientForm(forms.ModelForm):
    """
    Form to create new consumers.
    """
    class Meta:
        model = Client
        fields = ('name', 'url', 'redirect_uri', 'client_type')

    def save(self, user=None, **kwargs):
        self.instance.user = user
        return super(ClientForm, self).save(**kwargs)


class ClientAuthForm(forms.Form):
    """
    Client authentication form. Required to make sure that we're dealing with a
    real client. Form is used in :attr:`provider.oauth2.backends` to validate
    the client.
    """
    client_id = forms.CharField()
    client_secret = forms.CharField()

    def clean(self):
        data = self.cleaned_data
        try:
            client = Client.objects.get(client_id=data.get('client_id'),
                                        client_secret=data.get('client_secret'))
        except Client.DoesNotExist:
            raise ERROR_HANDLER(
                'Client could not be validated with key pair.')

        data['client'] = client
        return data


class ScopeModelChoiceField(forms.ModelMultipleChoiceField):

    # widget = forms.TextInput

    def to_python(self, value):
        if isinstance(value, string_types):
            return [s for s in value.split(' ') if s != '']
        elif isinstance(value, list):
            value_list = list()
            for item in value:
                value_list.extend(self.to_python(item))
            return value_list
        else:
            return value

    def clean(self, value):
        if self.required and not value:
            raise ERROR_HANDLER(
                'required_'+self.error_messages['required'])
        value_list = self.to_python(value)
        return super(ScopeModelChoiceField, self).clean(value_list)


class ScopeModelMixin(object):
    def clean_scope(self):
        default = Scope.objects.filter(name__in=DEFAULT_SCOPE.split(' '))
        scope_qs = self.cleaned_data.get('scope', default)
        if scope_qs:
            return scope_qs
        else:
            return default


class AuthorizationRequestForm(ScopeModelMixin, OAuthForm):
    """
    This form is used to validate the request data that the authorization
    endpoint receives from clients.

    Included data is specified in :rfc:`4.1.1`.
    """
    # Setting all required fields to false to explicitly check by hand
    # and use custom error messages that can be reused in the OAuth2
    # protocol
    response_type = forms.CharField(required=False)
    """
    ``"code"`` or ``"token"`` depending on the grant type.
    """

    redirect_uri = forms.URLField(required=False)
    """
    Where the client would like to redirect the user
    back to. This has to match whatever value was saved while creating
    the client.
    """

    state = forms.CharField(required=False)
    """
    Opaque - just pass back to the client for validation.
    """

    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)
    """
    The scope that the authorization should include.
    """

    def clean_response_type(self):
        """
        :rfc:`3.1.1` Lists of values are space delimited.
        """
        response_type = self.cleaned_data.get('response_type')

        if not response_type:
            raise ERROR_HANDLER('invalid_response_type.')

        types = response_type.split(" ")

        for type in types:
            if type not in RESPONSE_TYPE_CHOICES:
                raise ERROR_HANDLER('unsupported_response_type')

        return response_type

    def clean_redirect_uri(self):
        """
        :rfc:`3.1.2` The redirect value has to match what was saved on the
            authorization server.
        """
        redirect_uri = self.cleaned_data.get('redirect_uri')

        if redirect_uri:
            if not redirect_uri == self.client.redirect_uri:
                raise ERROR_HANDLER('invalid_request')

        return redirect_uri


class AuthorizationForm(ScopeModelMixin, OAuthForm):
    """
    A form used to ask the resource owner for authorization of a given client.
    """
    authorize = forms.BooleanField(required=False)
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)

    def save(self, **kwargs):
        authorize = self.cleaned_data.get('authorize')

        if not authorize:
            return None

        grant = Grant(**kwargs)
        grant.save()
        grant.scope.set(self.cleaned_data.get('scope'))
        return grant


class RefreshTokenGrantForm(ScopeModelMixin, OAuthForm):
    """
    Checks and returns a refresh token.
    """

    def __init__(self, refresh_token, client, scope):
        self.refresh_token = refresh_token
        self.client = client
        self.scope = scope
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)

    def clean_refresh_token(self):
        token = self.refresh_token

        if not token:
            raise ERROR_HANDLER('invalid_request')

        try:
            token = RefreshToken.objects.get(token=token,
                                             expired=False, client=self.client)
        except RefreshToken.DoesNotExist:
            raise ERROR_HANDLER('invalid_grant')

        return token

    def clean(self):
        """
        Make sure that the scope is less or equal to the previous scope!
        """
        refresh_token = self.clean_refresh_token()
        data = {}

        want_scope = {self.scope}
        access_token = getattr(refresh_token, 'access_token', None) if \
            refresh_token else \
            None
        if refresh_token and want_scope:
            has_scope = {s.name for s in access_token.scope.all()}
            if want_scope.issubset(has_scope):
                data['refresh_token'] = refresh_token
                return data
        raise ERROR_HANDLER('invalid_grant')


class AuthorizationCodeGrantForm(ScopeModelMixin, OAuthForm):
    """
    Check and return an authorization grant.
    """
    code = forms.CharField(required=False)
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)

    def clean_code(self):
        code = self.cleaned_data.get('code')

        if not code:
            raise ERROR_HANDLER('invalid_request')

        try:
            self.cleaned_data['grant'] = Grant.objects.get(
                code=code, client=self.client, expires__gt=now())
        except Grant.DoesNotExist:
            raise ERROR_HANDLER('invalid_grant')

        return code

    def clean(self):
        """
        Make sure that the scope is less or equal to the scope allowed on the
        grant!
        """
        data = self.cleaned_data
        want_scope = data.get('scope') or None
        grant = data.get('grant')
        if want_scope and grant:
            has_scope = {s.name for s in grant.scope.all()}
            want_scope = {s.name for s in want_scope}
            if want_scope.issubset(has_scope):
                return data
        raise ERROR_HANDLER('invalid_grant')


class PasswordGrantForm(ScopeModelMixin, OAuthForm):
    """
    Validate the password of a user on a password grant request.
    """

    def __init__(self, username, password, scope, client):
        self.username = username
        self.password = password
        self.scope = {scope}
    scope = ScopeModelChoiceField(
        queryset=Scope.objects.all(), required=False)

    def clean_username(self):
        if not self.username:
            raise ERROR_HANDLER('invalid_request')

        return self.username

    def clean_password(self):
        if not self.password:
            raise ERROR_HANDLER('invalid_request')

        return self.password

    def clean(self):
        data = {}
        self.clean_username()
        self.clean_password()
        user = authenticate(username=self.username,
                            password=self.password)

        if user is None:
            raise ERROR_HANDLER('invalid_grant')

        data['user'] = user
        data['scope'] = self.scope

        return data


class PublicPasswordGrantForm(PasswordGrantForm):
    client_id = forms.CharField(required=True)
    grant_type = forms.CharField(required=True)

    def clean_grant_type(self):
        if self.grant_type != 'password':
            raise ERROR_HANDLER('invalid_grant')

        return self.grant_type

    def clean(self):
        data = super(PublicPasswordGrantForm, self).clean()

        try:
            client = Client.objects.get(client_id=self.client_id)
        except Client.DoesNotExist:
            raise ERROR_HANDLER('invalid_client')

        if client.client_type != PUBLIC:
            raise ERROR_HANDLER('invalid_client')

        data['client'] = client
        return data


class PublicClientForm(OAuthForm):
    client_id = forms.CharField(required=True)
    grant_type = forms.CharField(required=True)
    code = forms.CharField(required=True)
    redirect_uri = forms.CharField(required=False)

    def clean_grant_type(self):
        if self.grant_type != 'authorization_code':
            raise ERROR_HANDLER('invalid_grant')

        return self.grant_type

    def clean(self):
        data = super().clean()
        try:
            client = Client.objects.get(
                client_id=data.get('client_id'),
                client_type=PUBLIC,
                allow_public_token=True,
            )
        except Client.DoesNotExist:
            raise ERROR_HANDLER('invalid_client')
        now = timezone.now().astimezone(timezone.get_current_timezone())
        try:
            redirect_uri = data.get('redirect_uri')
            grant = Grant.objects.get(
                client=client,
                code=data['code'],
            )
            if grant.redirect_uri and grant.redirect_uri != data.get('redirect_uri'):
                raise ERROR_HANDLER('invalid_client')
            if grant.expires < now:
                raise ERROR_HANDLER('invalid_client')
        except Grant.DoesNotExist:
            raise ERROR_HANDLER('invalid_grant')

        data['client'] = client
        data['grant'] = grant
        return data
