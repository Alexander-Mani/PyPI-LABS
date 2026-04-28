#!/bin/bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install --require-hashes --no-deps -r requirements/requirements.txt
DEPLOY_PHASE=setup bash deployment.sh 
DEPLOY_PHASE=smoke bash deployment.sh

