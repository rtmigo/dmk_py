#!/bin/bash
set -e && cd "${0%/*}"

pip install --upgrade pip
pip3 install -e .
pip3 install -r requirements.txt