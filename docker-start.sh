#! /usr/bin/env sh

exec pipenv run gunicorn -k "uvicorn.workers.UvicornWorker" -c "/conf/gunicorn_conf.py" "main:application"