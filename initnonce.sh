#!/usr/bin/env bash

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


# Exit immediately if a command fails, or if a variable is unset
set -euo pipefail

# 1. Read from the first argument ($1), or fallback to the default path
FIFO_PATH="${1:-/tmp/vault_fifo}"

# 2. Check if the path exists at all
if [ ! -e "$FIFO_PATH" ]; then
    echo "Fifo $FIFO_PATH is not available for writing!" >&2
    exit 1
fi

# 3. Test whether the existing path is indeed a FIFO (named pipe)
if [ ! -p "$FIFO_PATH" ]; then
    echo "Error: Path $FIFO_PATH exists but is not a FIFO!" >&2
    exit 1
fi

echo "Using FIFO path: $FIFO_PATH" >&2
echo "Waiting for reader to connect..." >&2

# 4. Open the FIFO for writing via file descriptor 3
# This line BLOCKS until your Python script opens the FIFO for reading
exec 3> "$FIFO_PATH"

# 5. Read the password securely (-s hides the echo input)
# -r prevents backslashes from acting as escape characters
read -rs -p "Enter Secret: " password
echo "" >&2 # Print a newline since 'read -s' does not

# 6. Write the password to the FIFO and close it
echo -n "$password" >&3

# 7. Explicitly close the file descriptor to signal EOF to Python
exec 3>&-

echo "Secret sent successfully." >&2