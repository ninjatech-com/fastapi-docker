#!/usr/bin/env sh
# from https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9

# No passphrase

ssh-keygen -t rsa -N '' -b 4096 -m PEM -f jwtRS256.key

openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
