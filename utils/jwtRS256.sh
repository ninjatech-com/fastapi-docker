#!/usr/bin/env sh

openssl genrsa -out jwtRS256.pem 2048
base64 < jwtRS256.pem -w 0 > jwtRS256.base64

openssl rsa -in jwtRS256.pem -pubout > jwtRS256.pem.pub
base64 < jwtRS256.pem.pub -w 0 > jwtRS256.base64.pub
