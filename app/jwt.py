from base64 import standard_b64decode
import datetime
import os
import time
from typing import Dict, Optional

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from jose import JWTError, jws, jwt

import pydantic

from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

TOKEN_LIFETIME_SECONDS = os.environ.get('TOKEN_LIFETIME_SECONDS') or 60 * 60
TOKEN_LIFETIME_SECONDS = int(TOKEN_LIFETIME_SECONDS)  # convert if it came in from the environment


class BearerToken(pydantic.BaseModel):
    access_token: str
    token_type: str


def get_private_key() -> str:
    # I had billions of problems with multiline entries in my .env file, so I base64 encode the RSA keys for environment
    # variables
    key = standard_b64decode(os.environ['JWT_PRIVATE_KEY']).decode('utf-8')
    return key


def get_public_key() -> str:
    # I had billions of problems with multiline entries in my .env file, so I base64 encode the RSA keys for environment
    # variables
    key = standard_b64decode(os.environ['JWT_PUBLIC_KEY']).decode('utf-8')
    return key


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
            claims = jwt.decode(jwt_token, get_public_key(), self.ALGORITHM)
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
        encoded = jws.sign(claims_to_encode, get_private_key(), algorithm=cls.ALGORITHM)

        return encoded
