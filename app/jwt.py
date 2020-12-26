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

import rsa

TOKEN_LIFETIME_SECONDS = os.environ.get('TOKEN_LIFETIME_SECONDS') or 60 * 60
TOKEN_LIFETIME_SECONDS = int(TOKEN_LIFETIME_SECONDS)  # convert if it came in from an environment variable


class BearerToken(pydantic.BaseModel):
    """
    Data for a token type
    """
    access_token: str
    token_type: str


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
            claims = jwt.decode(jwt_token, rsa.get_public_key_bytes().decode('utf-8'), self.algo)
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
        encoded = jws.sign(claims_to_encode, rsa.get_private_key_str(), algorithm=algorithm)

        return encoded
