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
    access_token: str
    token_type: str


def get_private_key() -> rsa.RSAPrivateKey:
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
    privkey = get_private_key()
    privstr = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return privstr.decode('utf-8')


def get_public_key() -> rsa.RSAPublicKey:

    global __public_key

    if not __public_key:
        privkey = get_private_key()
        __public_key = privkey.public_key()

    return __public_key


def get_public_key_bytes() -> bytes:
    pubkey = get_public_key()
    pubbytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pubbytes


def get_public_key_b64() -> bytes:
    global __public_key_b64
    if not __public_key_b64:
        __public_key_b64 = standard_b64encode(get_public_key_bytes())
    return __public_key_b64


class JWTBearerRS256(HTTPBearer):
    ALGORITHM = 'RS256'

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    def verify_jwt(self, jwt_token: str) -> dict:
        """
        Verifies the token's signature and delivers the claims if the token is valid.
        :param jwt_token: the bearer token string
        :return: dict of claims
        :raises HTTPException if there are issues with the tokens or claims
        """

        # TODO: beef up claims validation

        try:
            header = jwt.get_unverified_header(jwt_token)
        except JWTError:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail='JWK invalid')

        if header['alg'] != self.ALGORITHM:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail='JWK invalid')

        try:
            claims = jwt.decode(jwt_token, get_public_key_bytes().decode('utf-8'), self.ALGORITHM)
        except JWTError:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail='JWK invalid')

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

    @classmethod
    def create_access_token(cls, claims: Dict, expires_delta: Optional[datetime.timedelta]) -> str:
        """
        Create a signed access token with claims
        :param claims: the claims to put in the key
        :param expires_delta: how long the token is good for
        :return: a JWT string
        """
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
        encoded = jws.sign(claims_to_encode, get_private_key_str(), algorithm=cls.ALGORITHM)

        return encoded
