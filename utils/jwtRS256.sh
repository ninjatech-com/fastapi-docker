#!/usr/bin/env sh

# base64url encoded private key
KEY=${JWT_PRIVATE_KEY:-$(openssl genrsa 2048 | base64 -w 0 | tr '/+' '_-')}

echo "$KEY"

