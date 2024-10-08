#!/usr/bin/env bash

apt update

apt install python3-pip python3.11-venv -y

#virtual env
python3 -m venv pvethemes
source pvethemes/bin/activate
pip3 install -r requirements.txt

python3 PVEThemes.py

deactivate
