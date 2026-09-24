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

# Create config directory if it doesn't exist
mkdir -p config

echo "Generating self-signed cert non-interactively..."

# The -subj string provides all necessary answers to the prompts
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem \
  -keyout key.pem \
  -days 365 \
  -subj "/C=XX/ST=State/L=City/O=Organization/OU=Development/CN=127.0.0.1"

# Move the generated certificates to the config directory
mv cert.pem key.pem config/

echo "Generated self-signed cert in config folder..."
ls config/