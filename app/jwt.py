from base64 import standard_b64encode, standard_b64decode
import datetime
import os
import time
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from jose import JWTError, jws, jwt

import pydantic

from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

TOKEN_LIFETIME_SECONDS = os.environ.get('TOKEN_LIFETIME_SECONDS') or 60 * 60
TOKEN_LIFETIME_SECONDS = int(TOKEN_LIFETIME_SECONDS)  # convert if it came in from an environment variable

__private_key = None
__public_key = None
__public_key_b64 = None


class BearerToken(pydantic.BaseModel):
    """
    Data for a token type
    """
    access_token: str
    token_type: str


def get_private_key() -> rsa.RSAPrivateKey:
    """
    This will decode a base64 encoded private key in the JWT_PRIVATE_KEY environment variable, or create a new private
    key and cache it in the global __private_key variable as an RSAPrivateKey type
    :return: RSAPrivateKey instance
    """
    # I had billions of problems with multiline entries in my .env file, so I base64 encode the RSA keys for environment
    # variables
    global __private_key
    if not __private_key:
        if k := os.environ.get('JWT_PRIVATE_KEY'):
            __private_key = serialization.load_pem_private_key(standard_b64decode(k), password=None)
        else:
            # generate a private key
            __private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    return __private_key


def get_private_key_str() -> str:
    """
    Converts the private key to RSA PEM encoded utf-8 string
    :return: RSA PEM encoded private key string
    """
    privkey = get_private_key()
    privstr = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return privstr.decode('utf-8')


def get_public_key() -> rsa.RSAPublicKey:
    """
    Returns an RSAPublicKey for the private key, caches the key if it's not already cached
    :return: RSAPublicKey instance
    """

    global __public_key

    if not __public_key:
        privkey = get_private_key()
        __public_key = privkey.public_key()

    return __public_key


def get_public_key_bytes() -> bytes:
    """
    Gets the public key bytes
    :return: bytes of the RSA public key
    """

    pubkey = get_public_key()
    pubbytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pubbytes


def get_public_key_b64() -> bytes:
    """
    Gets a base64-encoded version of the public key, and caches it if it isn't already cacched
    :return: bytes - base64 encoded RSA public key
    """
    global __public_key_b64
    if not __public_key_b64:
        __public_key_b64 = standard_b64encode(get_public_key_bytes())
    return __public_key_b64


class JWTBearerRSA(HTTPBearer):
    """
    Support for creating and validating RSA tokens.
    """
    ALGORITHMS = {'RS256', 'RS384', 'RS512'}

    def __init__(self, auto_error: bool = True, algorithm='RS256'):
        super().__init__(auto_error=auto_error)
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm {algorithm}")
        self.algo = algorithm

    def verify_jwt(self, jwt_token: str) -> dict:
        """
        Verifies the token's signature and delivers the claims if the token is valid.
        :param jwt_token: the bearer token string
        :return: dict of claims
        :raises HTTPException if there are issues with the tokens or claims
        """

        try:
            header = jwt.get_unverified_header(jwt_token)
        except JWTError:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail='Invalid Header')

        if header['alg'] != self.algo:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail='Unsupported Algorithm')

        try:
            claims = jwt.decode(jwt_token, get_public_key_bytes().decode('utf-8'), self.algo)
        except JWTError:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail='Invalid Claims')

        return claims

    async def __call__(self, req: Request) -> dict:
        """
        Used as a FastAPI Depends to enforce JWT token validation.
        :param req: The request object
        :return: the claims section of the validated token
        :raises: HTTPException if there's an issue with the authorization
        """

        credentials: HTTPAuthorizationCredentials = await super().__call__(req)

        if credentials:
            if credentials.scheme != "Bearer":
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Wrong authentication method")

        data = self.verify_jwt(credentials.credentials)

        return data

    @staticmethod
    def create_access_token(
            algorithm: str = 'RS256',
            claims: Optional[Dict] = None,
            expires_delta: Optional[datetime.timedelta] = None
    ) -> str:
        """
        Create a signed access token with claims
        :param algorithm: the RSA algorithm to use - can be RS256, RS384, RS512
        :param claims: the claims to put in the key
        :param expires_delta: how long the token is good for
        :return: a JWT string
        """

        if algorithm not in JWTBearerRSA.ALGORITHMS:
            raise ValueError(f'Unsupported Algorithm {algorithm}')

        if claims is None:
            claims = dict()

        if not set(claims).isdisjoint({'iat', 'exp'}):
            # I don't want the caller to deliver the issued at time nor the expiration for security
            raise ValueError('Invalid claims')

        issued = time.time()
        claims_to_encode = claims.copy()
        if expires_delta:
            expire = issued + expires_delta.total_seconds()
        else:
            expire = issued + TOKEN_LIFETIME_SECONDS

        claims_to_encode['iat'] = issued
        claims_to_encode['exp'] = expire
        encoded = jws.sign(claims_to_encode, get_private_key_str(), algorithm=algorithm)

        return encoded
