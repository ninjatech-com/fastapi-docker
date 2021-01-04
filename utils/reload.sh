#!/bin/bash

pipenv run uvicorn --port 8000 --app-dir ../ app.main:application --reload
