import traceback
from typing import Dict

import jwt
import os
import requests
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import logging

_audience = 'Azure AD app ID for frontend web app'
if 'GUI_AD_APP_ID' in os.environ:
    _audience = os.environ['GUI_AD_APP_ID']

# url to updated keys for verifying tokens
_azure_key_url = 'https://login.microsoftonline.com/common/discovery/v2.0/keys'

key_cache = {}


# Looks up the correct key to verify token from token header kid
def _get_azure_key(kid):
    if kid not in key_cache:
        keys = requests.get(_azure_key_url).json()['keys']
        for key in keys:
            key_cache[key['kid']] = key
            if key['kid'] == kid:
                return key['x5c'][0]
    if kid not in key_cache:
        raise LookupError('The key list in azure contains no key with kid: ' + kid)
    key = key_cache[kid]
    return key['x5c'][0]


def _validate_token(auth_header):
    token = auth_header.split()[1]
    token_header = jwt.get_unverified_header(token)
    key = _get_azure_key(token_header['kid'])
    pem_start = '-----BEGIN CERTIFICATE-----\n'
    pem_end = '\n-----END CERTIFICATE-----\n'
    cert_str = pem_start + key + pem_end
    cert_obj = load_pem_x509_certificate(cert_str.encode('utf8'), default_backend())
    public_key = cert_obj.public_key()
    decoded = jwt.decode(token, public_key, algorithms=['RS256'], audience=_audience)

    # for testing with token in main method
    # decoded = jwt.decode(token, public_key, algorithms=['RS256'], audience=_audience, verify=False)

    return decoded


def authorize_lcoe_users(request):
    """
    :param request: Flask request object
    :return: Modified request object (change is also in-place)
    """
    if request.path == '/version.json':
        logging.info('Version requested, skipping auth check')
        return request
    # logging.info(request.method + ': request.json: ' + str(request.json))
    if request.method != 'OPTIONS':
        try:
            authorization_header = request.headers['Authorization']
        except:
            return 'A valid token in the authorization header is required to access the API.', 401
        try:
            decoded_token = _validate_token(authorization_header)

            username = decoded_token.get('unique_name').split('@')[0].lower()
            request.lcoe_username = username

            roles = decoded_token.get('roles')
            request.lcoe_roles = roles

            for role in roles:
                if role in ['admin', 'user']:
                    return request

            return 'User does not have the required role to access the service', 403
        except Exception as e:
            logging.error(traceback.format_exc())
            return str(e), 401


if __name__ == '__main__':
    _id_token = 'Bearer <paste your jwt here>'

    class Request:
        path: str
        headers: Dict[str, str]
        method: str

    req = Request()
    req.path = ''
    req.headers = {'Authorization': _id_token}
    req.method = ''
    request_after = authorize_lcoe_users(req)
    print(request_after)
