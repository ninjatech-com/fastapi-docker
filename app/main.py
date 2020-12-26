import datetime

from fastapi import Depends, FastAPI, HTTPException, status
import pydantic

from cors import setup_cors
from jwt import BearerToken, get_public_key_b64, JWTBearerRS256, TOKEN_LIFETIME_SECONDS


class LoginCredentials(pydantic.BaseModel):
    username: str
    password: str


application = FastAPI()
setup_cors(application)
auth = JWTBearerRS256()


@application.get("/")
async def root() -> dict:
    """
    I'm just here.
    :return: dict
    """
    return {"message": "Hello World"}


@application.get('/pubkey')
async def get_pubkey_b64():
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

    access_token = JWTBearerRS256.create_access_token(claims={"sub": user},
                                                      expires_delta=datetime.timedelta(seconds=TOKEN_LIFETIME_SECONDS))
    return {"access_token": access_token, "token_type": "bearer"}


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
