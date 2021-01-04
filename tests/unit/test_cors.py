from pytest_mock import MockerFixture

from app import cors


def test_setup_cors(mocker: MockerFixture) -> None:
    from fastapi.middleware.cors import CORSMiddleware
    origins = [
        "http://localhost",
        "http://localhost:8080",
    ]

    fakeapp = mocker.Mock()
    fakeapp.add_middleware = mocker.Mock()
    cors.setup_cors(fakeapp, origins)
    cors.setup_cors(fakeapp)
    assert fakeapp.add_middleware.call_count == 2
    args, kwargs = fakeapp.add_middleware.call_args_list[0]
    assert args[0] == CORSMiddleware
    assert kwargs == {
        'allow_origins': origins,
        'allow_credentials': True,
        'allow_methods': ['*'],
        'allow_headers': ['*']
    }

    # check out the default args version too
    args, kwargs = fakeapp.add_middleware.call_args_list[1]
    assert args[0] == CORSMiddleware
    assert kwargs == {
        'allow_origins': cors.default_origins,
        'allow_credentials': True,
        'allow_methods': ['*'],
        'allow_headers': ['*']
    }
