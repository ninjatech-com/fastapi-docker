from base64 import standard_b64encode, standard_b64decode
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

__private_key = None
__public_key = None
__public_key_b64 = None


def get_private_key() -> rsa.RSAPrivateKey:
    """
    This will decode a base64 encoded private key in the JWT_PRIVATE_KEY environment variable, or create a new private
    key and cache it in the global __private_key variable as an RSAPrivateKey type
    :return: RSAPrivateKey instance
    """
    # I had billions of problems with multiline entries in my .env file, so I base64 encode the RSA keys for environment
    # variables
    global __private_key
    if not __private_key:
        if k := os.environ.get('JWT_PRIVATE_KEY'):
            __private_key = serialization.load_pem_private_key(standard_b64decode(k), password=None)
        else:
            # generate a private key
            __private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    return __private_key


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

    global __public_key

    if not __public_key:
        privkey = get_private_key()
        __public_key = privkey.public_key()

    return __public_key


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
    global __public_key_b64
    if not __public_key_b64:
        __public_key_b64 = standard_b64encode(get_public_key_bytes())
    return __public_key_b64
