import base64

from provider.utils import now
from provider.oauth2.forms import ClientAuthForm, PublicPasswordGrantForm, PublicClientForm
from provider.oauth2.models import AccessToken


class BaseBackend(object):
    """
    Base backend used to authenticate clients as defined in :rfc:`1` against
    our database.
    """

    def authenticate(self, request=None):
        """
        Override this method to implement your own authentication backend.
        Return a client or ``None`` in case of failure.
        """
        pass


class BasicClientBackend(object):
    """
    Backend that tries to authenticate a client through HTTP authorization
    headers as defined in :rfc:`2.3.1`.
    """

    def authenticate(self, auth):

        if auth is None or auth == '':
            return None

        try:
            basic, enc_user_passwd = auth.split(' ')
            user_pass = base64.b64decode(enc_user_passwd).decode('utf8')
            self.client_id, self.client_secret = user_pass.split(':')

            form = ClientAuthForm({
                'client_id': self.client_id,
                'client_secret': self.client_secret})

            if form.is_valid():
                return form.cleaned_data.get('client')
            return None

        except ValueError:
            # Auth header was malformed, unpacking went wrong
            return None


class RequestParamsClientBackend(object):
    """
    Backend that tries to authenticate a client through request parameters
    which might be in the request body or URI as defined in :rfc:`2.3.1`.
    """

    def authenticate(self, client):
        return client


class PublicPasswordBackend(object):
    """
    Backend that tries to authenticate a client using username, password
    and client ID. This is only available in specific circumstances:

     - grant_type is "password"
     - client.client_type is 'public'
    """

    def authenticate(self, client):
        return client


class PublicClientBackend(object):
    def authenticate(self, client):
        return client


class AccessTokenBackend(object):
    """
    Authenticate a user via access token and client object.
    """

    def authenticate(self, access_token=None, client=None):
        try:
            return AccessToken.objects.get(token=access_token,
                                           expires__gt=now(), client=client)
        except AccessToken.DoesNotExist:
            return None
