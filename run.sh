#!/usr/bin/env bash

export FLASK_ENV=development
export FLASK_APP=app.py

flask run --host=0.0.0.0 --port=5001
