"""
Dailymile OAuth support.
"""
import cgi
import json
from urllib import urlencode
from urllib2 import urlopen, HTTPError
import base64
import hmac
import hashlib
import time

from django.utils import simplejson
from django.contrib.auth import authenticate

from social_auth.backends import BaseOAuth2, OAuthBackend, USERNAME
from social_auth.utils import setting
from social_auth.backends.exceptions import AuthException, AuthCanceled, \
                                            AuthFailed, AuthUnknownError


json_decoder = json.JSONDecoder()



class DailymileBackend(OAuthBackend):
    """dailymile OAuth2 authentication backend"""
    name = 'dailymile'

    def get_user_id(self, details, response):
        return response['username']

    def get_user_details(self, response):
        return {
            USERNAME: response['username'],
            'email': '',
        }


class DailymileAuth(BaseOAuth2):
    """dailymile OAuth2 support"""
    AUTH_BACKEND = DailymileBackend
    RESPONSE_TYPE = 'code'
    SCOPE_SEPARATOR = ','
    AUTHORIZATION_URL = 'https://api.dailymile.com/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://api.dailymile.com/oauth/token?grant_type=authorization_code'
    PEOPLE_URL = 'https://api.dailymile.com/people/me.json'
    SETTINGS_KEY_NAME = 'DAILYMILE_CLIENT_ID'
    SETTINGS_SECRET_NAME = 'DAILYMILE_CLIENT_SECRET'
    SCOPE_VAR_NAME = 'DAILYMILE_EXTENDED_PERMISSIONS'

    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        access_token = None
        expires = None

        if 'code' in self.data:
            data = urlencode({
                'code': self.data['code'],
                'redirect_uri': self.redirect_uri,
                'client_id': setting('DAILYMILE_CLIENT_ID'),
                'client_secret': setting('DAILYMILE_CLIENT_SECRET'),
            })
            try:
                response = json_decoder.decode(urlopen(self.ACCESS_TOKEN_URL, data).read())
            except HTTPError:
                raise AuthFailed(self, 'There was an error authenticating the app')

            access_token = response['access_token']
            if 'expires' in response:
                    expires = response['expires']

        if 'signed_request' in self.data:
            response = load_signed_request(self.data.get('signed_request'))

            if response is not None:
                access_token = response.get('access_token') or \
                               response.get('oauth_token') or \
                               self.data.get('access_token')

                if 'expires' in response:
                    expires = response['expires']

        if access_token:
            data = self.user_data(access_token)

            if not isinstance(data, dict):
                # From time to time dailymile responds back a JSON with just
                # False as value, the reason is still unknown, but since the
                # data is needed (it contains the user ID used to identify the
                # account on further logins), this app cannot allow it to
                # continue with the auth process.
                raise AuthUnknownError(self, 'An error ocurred while ' \
                                             'retrieving users dailymile ' \
                                             'data')

            data['access_token'] = access_token
            # expires will not be part of response if offline access
            # premission was requested
            if expires:
                data['expires'] = response['expires'][0]

            kwargs.update({'auth': self,
                           'response': data,
                           self.AUTH_BACKEND.name: True})

            return authenticate(*args, **kwargs)
        else:
            if self.data.get('error') == 'access_denied':
                raise AuthCanceled(self)
            else:
                raise AuthException(self)

    def user_data(self, access_token, *args, **kwargs):
        return json_decoder.decode(urlopen(self.PEOPLE_URL + '?oauth_token=%s' % access_token).read())

    @classmethod
    def enabled(cls):
        """Return backend enabled status by checking basic settings"""
        return setting('DAILYMILE_CLIENT_ID') and setting('DAILYMILE_CLIENT_SECRET')


def base64_url_decode(data):
    data = data.encode(u'ascii')
    data += '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data)


def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')


def load_signed_request(signed_request):
    try:
        sig, payload = signed_request.split(u'.', 1)
        sig = base64_url_decode(sig)
        data = simplejson.loads(base64_url_decode(payload))

        expected_sig = hmac.new(setting('DAILYMILE_CLIENT_SECRET'),
                                msg=payload,
                                digestmod=hashlib.sha256).digest()

        # allow the signed_request to function for upto 1 day
        if sig == expected_sig and \
                data[u'issued_at'] > (time.time() - 86400):
            return data
    except ValueError:
        pass  # ignore if can't split on dot


# Backend definition
BACKENDS = {
    'dailymile': DailymileAuth,
}
