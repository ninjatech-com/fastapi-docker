import datetime

from fastapi import Depends, FastAPI, HTTPException, status
import pydantic

from .cors import setup_cors
from .jwt import BearerToken, JWTBearerRS256, TOKEN_LIFETIME_SECONDS


class LoginCredentials(pydantic.BaseModel):
    username: str
    password: str


app = FastAPI()
setup_cors(app)
auth = JWTBearerRS256()


@app.get("/")
async def root() -> dict:
    """
    I'm just here.
    :return: dict
    """
    return {"message": "Hello World"}


async def authenticate_user(creds: LoginCredentials) -> str:
    """
    Placeholder for user/pass validation
    :param creds: the login credentials
    :return: the user name
    """
    return "username"


@app.post("/auth/token", response_model=BearerToken)
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

    access_token = JWTBearerRS256.create_access_token(claims={"sub": user}, expires_delta=TOKEN_LIFETIME_SECONDS)
    return {"access_token": access_token, "token_type": "bearer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
