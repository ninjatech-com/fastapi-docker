from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# TODO: better if these parameters are not hardcoded

origins = [
    "http://localhost",
    "http://localhost:8080",
]


def setup_cors(app: FastAPI) -> None:
    """
    Configures CORS
    :param app: the FastAPI app instance
    :return: None
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
