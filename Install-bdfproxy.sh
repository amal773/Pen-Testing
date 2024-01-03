#!/bin/bash
cd /opt
git clone https://github.com/secretsquirrel/BDFProxy.git
cd BDFProxy
./install.sh
apt -y install python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
pip install capstone mitmproxy==0.13
