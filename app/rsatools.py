from base64 import urlsafe_b64encode, urlsafe_b64decode
import logging
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_private_key = None
_public_key = None
_public_key_b64 = None


def get_private_key() -> rsa.RSAPrivateKey:
    """
    This will decode a base64 encoded private key in the JWT_PRIVATE_KEY environment variable, or create a new private
    key and cache it in the global __private_key variable as an RSAPrivateKey type
    :return: RSAPrivateKey instance
    """
    # I had billions of problems with multiline entries in my .env file, so I base64url encode
    # the RSA keys for environment variables
    global _private_key
    if not _private_key:
        if k := os.environ.get('JWT_PRIVATE_KEY'):
            _private_key = serialization.load_pem_private_key(urlsafe_b64decode(k), password=None)
        else:
            # generate a private key
            # note that running a multi-process version of this via something like gunicorn
            # means that each process will get a different private key, so this is really just
            # to make debugging easier.
            _private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    return _private_key


def get_private_key_str() -> str:
    """
    Converts the private key to RSA PEM encoded utf-8 string
    :return: RSA PEM encoded private key string
    """
    privkey = get_private_key()
    privstr = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return privstr.decode('utf-8')


def get_public_key() -> rsa.RSAPublicKey:
    """
    Returns an RSAPublicKey for the private key, caches the key if it's not already cached
    :return: RSAPublicKey instance
    """

    global _public_key

    if not _public_key:
        privkey = get_private_key()
        _public_key = privkey.public_key()

    return _public_key


def get_public_key_bytes() -> bytes:
    """
    Gets the public key bytes
    :return: bytes of the RSA public key
    """

    pubkey = get_public_key()
    pubbytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pubbytes


def get_public_key_b64() -> bytes:
    """
    Gets a base64-encoded version of the public key, and caches it if it isn't already cacched
    :return: bytes - base64 encoded RSA public key
    """
    global _public_key_b64
    if not _public_key_b64:
        _public_key_b64 = urlsafe_b64encode(get_public_key_bytes())
    return _public_key_b64
