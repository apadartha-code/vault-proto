#!/bin/bash

# Copyright (C) 2026  https://github.com/apadartha-code
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://gnu.org>.


# Exit immediately if a command exits with a non-zero status
set -e

pushd $(dirname $0) >/dev/null
BASEDIR=$(pwd)

echo "Creating virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

DEPDIR=dependencies
echo "Creating dependencies folder..."
mkdir $DEPDIR

echo "Downloading backend (keymaker-proto) in peer folder..."
pushd $DEPDIR && git clone https://github.com/apadartha-code/keymaker-proto.git

echo "Installing backend package in current virtual environment..."
cd keymaker-proto && pip install -e .
popd

echo "Downloading keymaker UI blueprint (keymaker-ui) in peer folder..."
pushd $DEPDIR && git clone https://github.com/apadartha-code/keymaker-ui.git

echo "Installing backend package in current virtual environment..."
cd keymaker-ui && pip install -e .
popd

echo "Generating self-signed certs..."
./cert.sh

echo "Setup complete!"
echo "Run 'source venv/bin/activate && python app.py' to start the application."
echo "Then go to 'https://127.0.0.1:5000/' in your browser."

popd >/dev/null

