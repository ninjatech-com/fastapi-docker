import datetime

from fastapi import Depends, FastAPI, HTTPException, status
import pydantic

from cors import setup_cors
from jwt import BearerToken, JWTBearerRSA, TOKEN_LIFETIME_SECONDS
from rsa import get_public_key_b64


class LoginCredentials(pydantic.BaseModel):
    """
    The username and password used to authenticate
    """
    username: str
    password: str


application = FastAPI()
setup_cors(application)
auth = JWTBearerRSA()


@application.get("/")
async def root() -> dict:
    """
    I'm just here.
    :return: dict
    """
    return {"message": "Hello World"}


@application.get('/pubkey')
async def get_pubkey_b64():
    """
    Get the RSA PEM encoded public key in base64 encoding
    :return: str
    """
    return get_public_key_b64()


async def authenticate_user(creds: LoginCredentials) -> str:
    """
    Placeholder for user/pass validation
    :param creds: the login credentials
    :return: the user name
    """
    return "username"


@application.post("/auth/token", response_model=BearerToken)
async def login(credentials: LoginCredentials):
    """
    Validates credentials, returns authorization token
    :param credentials: the login credentials
    :return: a bearer token
    :raises HTTPException 401 if the credentials are not valid
    """

    user = await authenticate_user(credentials)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = JWTBearerRSA.create_access_token(
        algorithm='RS256',
        claims={"sub": user},
        expires_delta=datetime.timedelta(seconds=TOKEN_LIFETIME_SECONDS)
    )
    rv = BearerToken(access_token=access_token, token_type='bearer')
    return rv


@application.get("/secure", dependencies=[Depends(auth)])
async def mypage():
    """
    A secured page
    :return: placeholder
    """
    return {'place': 'holder'}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(application, host="0.0.0.0", port=8000)
