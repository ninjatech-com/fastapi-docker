import os
from typing import Optional

from passlib.apps import django_context
import psycopg2
import pydantic


class LoginCredentials(pydantic.BaseModel):
    """
    The username and password used to authenticate
    """
    user_email: str
    password: str


def _get_password_hash(user_email: str) -> Optional[str]:
    """
    Fetches a hashed password from a django database using the email address for an active superuser in the django
    system
    :param user_email: the email to look up
    :return: None or a hashed password
    """

    db_str = os.environ.get('DJANGO_DB_CONNECTION_STRING')

    if not db_str:
        return None

    cursor = psycopg2.connect(db_str).cursor()

    q = "select password from auth_user where email = %s and is_active = true and is_superuser = true"
    cursor.execute(q, (user_email,))
    return cursor.fetchone()


async def authenticate_user(creds: LoginCredentials) -> bool:
    """
    User/pass login
    :param creds: the login credentials
    :return: whether the credentials are valid
    """

    if pass_hash := _get_password_hash(creds.user_email):
        if django_context.verify(creds.password, pass_hash[0]):
            return True
        else:
            return False

    return False
