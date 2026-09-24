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

# hasher.py
import sys
import bcrypt

def main():
    try:
        # Read action type from the binary stdin buffer
        action = sys.stdin.buffer.readline().strip()
        
        if action == b"HASH":
            # Read plaintext password bytes directly (strip trailing newline)
            password = sys.stdin.buffer.readline().rstrip(b'\r\n')
            
            # Hash and write raw bytes back to stdout
            hashed = bcrypt.hashpw(password, bcrypt.gensalt())
            sys.stdout.buffer.write(hashed)
            
        elif action == b"VERIFY":
            # Read plaintext password and stored hash from binary buffer
            password = sys.stdin.buffer.readline().rstrip(b'\r\n')
            stored_hash = sys.stdin.buffer.readline().rstrip(b'\r\n')
            
            # Verify and print outcome
            matched = bcrypt.checkpw(password, stored_hash)
            sys.stdout.buffer.write(b"VALID" if matched else b"INVALID")
            
    except Exception as e:
        sys.stderr.write(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
