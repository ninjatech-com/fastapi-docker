import datetime

from fastapi import Depends, FastAPI, HTTPException, status

from app.cors import setup_cors
from app.jwtbearer import AUDIENCE, BearerToken, get_jwks, JWKKeySet, JWTBearerRSA, TOKEN_LIFETIME_SECONDS
import app.django_authenticate


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


@application.get('/jwks', response_model=JWKKeySet)
async def get_jwk_set():
    """
    Return the JWK(s)
    :return: JWKKeySet
    """

    return get_jwks()


@application.post("/auth/token", response_model=BearerToken)
async def login(credentials: django_authenticate.LoginCredentials):
    """
    Validates credentials, returns authorization token
    :param credentials: the login credentials
    :return: a bearer token
    :raises HTTPException 401 if the credentials are not valid
    """

    is_authenticated = await django_authenticate.authenticate_user(credentials)

    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = JWTBearerRSA.create_access_token(
        algorithm='RS256',
        claims={'sub': credentials.user_email, 'aud': AUDIENCE},
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
