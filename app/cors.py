from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# TODO: better if these parameters are not hardcoded
default_origins = [
    "http://localhost",
    "http://localhost:8080",
]


def setup_cors(app: FastAPI, origins: Optional[List[str]] = None) -> None:
    """
    Configures CORS
    :param app: the FastAPI app instance
    :param origins: the allowed origins for CORS
    :return: None
    """
    if origins is None:
        origins = default_origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
