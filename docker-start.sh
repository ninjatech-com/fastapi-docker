#! /usr/bin/env sh

# One important function of these environment variables is so that the workers started by gunicorn all have the same
# private key and jwk data

# create a private key for this container if the env var isn't set

# base64url encode this
KEY=${JWT_PRIVATE_KEY:-$(openssl genrsa 2048 | base64 -w 0 | tr '/+' '_-')}

JWKS=$(PYTHONPATH=/ JWT_PRIVATE_KEY="$KEY" pipenv run python /utils/private_key_to_jks.py)

exec pipenv run gunicorn -k "uvicorn.workers.UvicornWorker" -e JWT_PRIVATE_KEY="$KEY" -e JWT_JWKS="$JWKS" -c "/conf/gunicorn_conf.py" "app.main:application"
