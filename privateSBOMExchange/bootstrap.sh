#!/bin/bash
#set -x

if [ ! -e virtualenv ]
then
    echo "didn't identify a venv"
    python -m venv virtualenv
else
    echo "Using existing venv"
fi

source virtualenv/bin/activate
pip install -r requirements.txt
