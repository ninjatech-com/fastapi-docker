"""
Relies on the environment variable "JWT_PRIVATE_KEY" to be set to a base64url-encoded RSA private key
"""
import json
from app import jwtbearer

print(json.dumps(jwtbearer.get_jwks()))
