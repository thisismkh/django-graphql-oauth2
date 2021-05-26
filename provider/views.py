from __future__ import absolute_import

import json

from six.moves.urllib_parse import urlparse, ParseResult

from django.contrib.auth import authenticate
from django.http import HttpResponse
from django.http import HttpResponseRedirect, QueryDict
from django.utils.translation import ugettext as _
from django.views.generic.base import TemplateView, View
from django.core.exceptions import ObjectDoesNotExist
from graphql import GraphQLError
from provider.oauth2.models import Client, Scope
from provider import constants


class OAuthError(Exception):
    """
    Exception to throw inside any views defined in :attr:`provider.views`.

    Any :attr:`OAuthError` thrown will be signalled to the API consumer.

    :attr:`OAuthError` expects a dictionary as its first argument outlining the
    type of error that occured.

    :example:

    ::

        raise OAuthError({'error': 'invalid_request'})

    The different types of errors are outlined in :rfc:`4.2.2.1` and
    :rfc:`5.2`.

    """


class AuthUtilMixin(object):
    """
    Mixin providing common methods required in the OAuth view defined in
    :attr:`provider.views`.
    """

    def get_data(self, request, key='params'):
        """
        Return stored data from the session store.

        :param key: `str` The key under which the data was stored.
        """
        return request.session.get('%s:%s' % (constants.SESSION_KEY, key))

    def cache_data(self, request, data, key='params'):
        """
        Cache data in the session store.

        :param request: :attr:`django.http.HttpRequest`
        :param data: Arbitrary data to store.
        :param key: `str` The key under which to store the data.
        """
        request.session['%s:%s' % (constants.SESSION_KEY, key)] = data

    def clear_data(self, request):
        """
        Clear all OAuth related data from the session store.
        """
        for key in list(request.session.keys()):
            if key.startswith(constants.SESSION_KEY):
                del request.session[key]

    def authenticate(self, client):
        """
        Authenticate a client against all the backends configured in
        :attr:`authentication`.
        """
        for backend in self.authentication:
            client = backend().authenticate(auth=client)
            if client is not None:
                return client
        return None


class CaptureViewBase(AuthUtilMixin, TemplateView):
    """
    As stated in section :rfc:`3.1.2.5` this view captures all the request
    parameters and redirects to another URL to avoid any leakage of request
    parameters to potentially harmful JavaScripts.

    This application assumes that whatever web-server is used as front-end will
    handle SSL transport.

    If you want strict enforcement of secure communication at application
    level, set :attr:`settings.OAUTH_ENFORCE_SECURE` to ``True``.

    The actual implementation is required to override :meth:`get_redirect_url`.
    """
    template_name = 'provider/authorize.html'

    def get_redirect_url(self, request):
        """
        Return a redirect to a URL where the resource owner (see :rfc:`1`)
        authorizes the client (also :rfc:`1`).

        :return: :class:`django.http.HttpResponseRedirect`

        """
        raise NotImplementedError

    def validate_scopes(self, scope_list):
        raise NotImplementedError

    def handle(self, request, data):
        self.cache_data(request, data)

        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.render_to_response({'error': 'access_denied',
                                            'error_description': _("A secure connection is required."),
                                            'next': None},
                                           status=400)

        scope_list = [s for s in
                      data.get('scope', '').split(' ') if s != '']
        if self.validate_scopes(scope_list):
            return HttpResponseRedirect(self.get_redirect_url(request))
        else:
            return HttpResponse("Invalid scope.", status=400)


class AuthorizeViewBase(AuthUtilMixin, TemplateView):
    """
    View to handle the client authorization as outlined in :rfc:`4`.
    Implementation must override a set of methods:

    * :attr:`get_redirect_url`
    * :attr:`get_request_form`
    * :attr:`get_authorization_form`
    * :attr:`get_client`
    * :attr:`save_authorization`

    :attr:`Authorize` renders the ``provider/authorize.html`` template to
    display the authorization form.

    On successful authorization, it redirects the user back to the defined
    client callback as defined in :rfc:`4.1.2`.

    On authorization fail :attr:`Authorize` displays an error message to the
    user with a modified redirect URL to the callback including the error
    and possibly description of the error as defined in :rfc:`4.1.2.1`.
    """
    template_name = 'provider/authorize.html'

    def get_redirect_url(self, request):
        """
        :return: ``str`` - The client URL to display in the template after
            authorization succeeded or failed.
        """
        raise NotImplementedError

    def get_request_form(self, client, data):
        """
        Return a form that is capable of validating the request data captured
        by the :class:`Capture` view.
        The form must accept a keyword argument ``client``.
        """
        raise NotImplementedError

    def get_authorization_form(self, request, client, data, client_data):
        """
        Return a form that is capable of authorizing the client to the resource
        owner.

        :return: :attr:`django.forms.Form`
        """
        raise NotImplementedError

    def get_client(self):
        """
        Return a client object from a given client identifier. Return ``None``
        if no client is found. An error will be displayed to the resource owner
        and presented to the client upon the final redirect.
        """
        # self.client_id
        raise NotImplementedError

    def save_authorization(self, request, client, form, client_data):
        """
        Save the authorization that the user granted to the client, involving
        the creation of a time limited authorization code as outlined in
        :rfc:`4.1.2`.

        Should return ``None`` in case authorization is not granted.
        Should return a string representing the authorization code grant.

        :return: ``None``, ``str``
        """
        raise NotImplementedError

    def has_authorization(self, request, client, scope_list):
        """
        Check to see if there is a previous authorization request with the
        requested scope permissions.

        :param request:
        :param client:
        :param scope_list:
        :return: ``False``, ``AuthorizedClient``
        """
        return False

    def _validate_client(self, request, data):
        """
        :return: ``tuple`` - ``(client or False, data or error)``
        """
        client = self.get_client(self.client_id)

        if client is None:
            raise constants.ERROR_HANDLER('unauthorized_client')

        form = self.get_request_form(client, data)

        if not form.is_valid():
            return form.errors

        return client, form.cleaned_data

    def error_response(self, request, error, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes
        awry. Errors can include invalid clients, authorization denials and
        other edge cases such as a wrong ``redirect_uri`` in the authorization
        request.

        :param request: :attr:`django.http.HttpRequest`
        :param error: ``dict``
            The different types of errors are outlined in :rfc:`4.2.2.1`
        """
        ctx = {}
        ctx.update(error)

        # If we got a malicious redirect_uri or client_id, remove all the
        # cached data and tell the resource owner. We will *not* redirect back
        # to the URL.

        if error.get('error') in ['redirect_uri', 'unauthorized_client']:
            ctx.update(next='/')
            return self.render_to_response(ctx, **kwargs)

        ctx.update(next=self.get_redirect_url(request))

        return self.render_to_response(ctx, **kwargs)

    def handle(self, request, post_data=None):
        data = self.get_data(request)

        if data is None:
            return self.error_response(request, {
                'error': 'expired_authorization',
                'error_description': _('Authorization session has expired.')})

        try:
            client, data = self._validate_client(request, data)
        except OAuthError as e:
            return self.error_response(request, e.args[0], status=400)

        scope_list = [s.name for s in
                      data.get('scope', [])]
        if self.has_authorization(request, client, scope_list):
            post_data = {
                'scope': scope_list,
                'authorize': u'Authorize',
            }

        authorization_form = self.get_authorization_form(request, client,
                                                         post_data, data)

        if not authorization_form.is_bound or not authorization_form.is_valid():
            return self.render_to_response({
                'client': client,
                'form': authorization_form,
                'oauth_data': data,
            })

        code = self.save_authorization(request, client,
                                       authorization_form, data)

        # be sure to serialize any objects that aren't natively json
        # serializable because these values are stored as session data
        data['scope'] = scope_list
        self.cache_data(request, data)
        self.cache_data(request, code, "code")
        self.cache_data(request, client.pk, "client_pk")

        return HttpResponseRedirect(self.get_redirect_url(request))


class RedirectViewBase(AuthUtilMixin, View):
    """
    Redirect the user back to the client with the right query parameters set.
    This can be either parameters indicating success or parameters indicating
    an error.
    """

    def error_response(self, error, mimetype='application/json', status=400,
                       **kwargs):
        """
        Return an error response to the client with default status code of
        *400* stating the error as outlined in :rfc:`5.2`.
        """
        return HttpResponse(json.dumps(error), content_type=mimetype,
                            status=status, **kwargs)


class AccessTokenViewBase(AuthUtilMixin, TemplateView):
    """
    :attr:`AccessToken` handles creation and refreshing of access tokens.

    Implementations must implement a number of methods:

    * :attr:`get_authorization_code_grant`
    * :attr:`get_refresh_token_grant`
    * :attr:`get_password_grant`
    * :attr:`get_access_token`
    * :attr:`create_access_token`
    * :attr:`create_refresh_token`
    * :attr:`invalidate_grant`
    * :attr:`invalidate_access_token`
    * :attr:`invalidate_refresh_token`

    The default implementation supports the grant types defined in
    :attr:`grant_types`.

    According to :rfc:`4.4.2` this endpoint too must support secure
    communication. For strict enforcement of secure communication at
    application level set :attr:`settings.OAUTH_ENFORCE_SECURE` to ``True``.

    According to :rfc:`3.2` we can only accept POST requests.

    Returns with a status code of *400* in case of errors. *200* in case of
    success.
    """

    authentication = ()
    """
    Authentication backends used to authenticate a particular client.
    """

    grant_types = ['refresh_token', 'password']
    """
    The default grant types supported by this view.
    """

    def __init__(self, client, grant_type, scope, username, password, refresh_token):
        self.client = client
        self.grant_type = grant_type
        self.scope = scope
        self.username = username
        self.password = password
        self.refresh = refresh_token

    def get_authorization_code_grant(self, data, client):
        """
        Return the grant associated with this request or an error dict.

        :return: ``tuple`` - ``(True or False, grant or error_dict)``
        """
        raise NotImplementedError

    def get_refresh_token_grant(self, data, client):
        """
        Return the refresh token associated with this request or an error dict.

        :return: ``tuple`` - ``(True or False, token or error_dict)``
        """
        raise NotImplementedError

    def get_password_grant(self, username, password, client):
        """
        Return a user associated with this request or an error dict.

        :return: ``tuple`` - ``(True or False, user or error_dict)``
        """
        raise NotImplementedError

    def get_access_token(self, user, scope, client):
        """
        Override to handle fetching of an existing access token.

        :return: ``object`` - Access token
        """
        raise NotImplementedError

    def create_access_token(self, user, scope, client):
        """
        Override to handle access token creation.

        :return: ``object`` - Access token
        """
        raise NotImplementedError

    def create_refresh_token(self, user, scope, access_token, client):
        """
        Override to handle refresh token creation.

        :return: ``object`` - Refresh token
        """
        raise NotImplementedError

    def invalidate_grant(self, grant):
        """
        Override to handle grant invalidation. A grant is invalidated right
        after creating an access token from it.

        :return None:
        """
        raise NotImplementedError

    def invalidate_refresh_token(self, refresh_token):
        """
        Override to handle refresh token invalidation. When requesting a new
        access token from a refresh token, the old one is *always* invalidated.

        :return None:
        """
        raise NotImplementedError

    def invalidate_access_token(self, access_token):
        """
        Override to handle access token invalidation. When a new access token
        is created from a refresh token, the old one is *always* invalidated.

        :return None:
        """
        raise NotImplementedError

    def error_response(self, error, mimetype='application/json', status=400,
                       **kwargs):
        """
        Return an error response to the client with default status code of
        *400* stating the error as outlined in :rfc:`5.2`.
        """
        return HttpResponse(json.dumps(error), content_type=mimetype,
                            status=status, **kwargs)

    def access_token_response(self, access_token):
        """
        Returns a successful response after creating the access token
        as defined in :rfc:`5.1`.
        """

        response_data = {
            'access_token': access_token.token,
            'token_type': constants.TOKEN_TYPE,
            'expires_in': access_token.get_expire_delta(),
            'scope': access_token.get_scope_string(),
        }

        # Not all access_tokens are given a refresh_token
        # (for example, public clients doing password auth)
        try:
            rt = access_token.refresh_token
            response_data['refresh_token'] = rt.token
        except ObjectDoesNotExist:
            pass

        return response_data

    def authorization_code(self, client):
        """
        Handle ``grant_type=authorization_code`` requests as defined in
        :rfc:`4.1.3`.
        """
        grant = self.get_authorization_code_grant(client)
        at = self.create_access_token(grant.user,
                                      list(grant.scope.all()), client)

        suppress_refresh_token = False
        if client.client_type == constants.PUBLIC and client.allow_public_token:
            if not self.client_secret:
                suppress_refresh_token = True

        if not suppress_refresh_token:
            rt = self.create_refresh_token(grant.user,
                                           list(grant.scope.all()), at, client)

        self.invalidate_grant(grant)

        return self.access_token_response(at)

    def refresh_token(self, client):
        """
        Handle ``grant_type=refresh_token`` requests as defined in :rfc:`6`.
        """
        rt = self.get_refresh_token_grant(self.refresh, self.scope, client)

        token_scope = list(rt.access_token.scope.all())

        # this must be called first in case we need to purge expired tokens
        self.invalidate_refresh_token(rt)
        self.invalidate_access_token(rt.access_token)

        at = self.create_access_token(rt.user,
                                      token_scope,
                                      client)
        rt = self.create_refresh_token(at.user,
                                       at.scope.all(), at, client)

        return self.access_token_response(at)

    def password_grant(self, client):
        """
        Handle ``grant_type=password`` requests as defined in :rfc:`4.3`.
        """

        data = self.get_password_grant(
            self.username, self.password, self.scope, client)
        user = data['user']
        scope = data['scope']

        at = self.create_access_token(user, scope, client)
        # Public clients don't get refresh tokens
        if client.client_type != constants.PUBLIC:
            rt = self.create_refresh_token(user, scope, at, client)

        return self.access_token_response(at)

    def get_handler(self):
        """
        Return a function or method that is capable handling the ``grant_type``
        requested by the client or return ``None`` to indicate that this type
        of grant type is not supported, resulting in an error response.
        """
        if self.grant_type == 'refresh_token':
            return self.refresh_token
        elif self.grant_type == 'password':
            return self.password_grant
        return None

    def mutate(self):
        """
        Return requested values related to grant type
        """
        if not self.grant_type:
            raise constants.ERROR_HANDLER('without_grant_type')

        if self.grant_type not in self.grant_types:
            raise constants.ERROR_HANDLER('unsupported_grant_type')

        client = self.authenticate(self.client)

        if client is None:
            raise constants.ERROR_HANDLER('invalid_client')

        handler = self.get_handler()

        try:
            return handler(client)
        except OAuthError as e:
            raise constants.ERROR_HANDLER(e.args[0])
