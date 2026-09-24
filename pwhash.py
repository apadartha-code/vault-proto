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

# app.py
import subprocess
import sys

from security.framework import SingleUse

WORKER = "pwhash_worker.py"

# def subprocess_hash_password(plain_password: bytearray) -> str:
def subprocess_hash_password(passwd_wrapper: SingleUse) -> str:
    """Spins up an isolated process to hash a bytearray password securely."""
    with passwd_wrapper.revealed() as plain_password:
        # Construct binary payload using byte literals and byte concats
        payload_wrapper = SingleUse.concat(b"HASH\n", plain_password, b"\n")
    
    process = subprocess.Popen(
        [sys.executable, WORKER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False # Crucial: Operate entirely in raw binary mode
    )

    with payload_wrapper.revealed() as payload:
        stdout, stderr = process.communicate(input=payload)
    
    if process.returncode != 0:
        raise RuntimeError(f"Subprocess failed: {stderr.decode('utf-8').strip()}")
        
    # Return the hash as a standard string for database storage
    return stdout.decode('utf-8').strip()

# def subprocess_verify_password(plain_password: bytearray, stored_hash: str) -> bool:
def subprocess_verify_password(passwd_wrapper: SingleUse, stored_hash: str) -> bool:
    """Spins up an isolated process to verify a bytearray password safely."""
    with passwd_wrapper.revealed() as plain_password:
        # Construct binary payload using byte literals and byte concats
        payload_wrapper = SingleUse.concat(b"VERIFY\n", plain_password, b"\n", stored_hash.encode('utf-8'), b"\n")
    
    process = subprocess.Popen(
        [sys.executable, WORKER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False
    )
    
    with payload_wrapper.revealed() as payload:
        stdout, stderr = process.communicate(input=payload)
    
    if process.returncode != 0:
        raise RuntimeError(f"Subprocess failed: {stderr.decode('utf-8').strip()}")
        
    return stdout.strip() == b"VALID"

# --- Execution Demonstration ---
if __name__ == "__main__":
    # Create a mutable bytearray password
    password_buffer = bytearray(b"MyUltraSecurePassword2026!")
    
    print(f"Original Buffer before hashing: {password_buffer.decode('utf-8', errors='ignore')}")
    print("[*] Dispatching bytearray to subprocess...")

    wrapped_password = SingleUse(password_buffer)
    print(f"Original Buffer after hashing (wiped): {list(password_buffer)}") # All zeroes
    db_hash = subprocess_hash_password(wrapped_password)
    print(f"[+] Hashing Complete. Returned Hash: {db_hash}")
    wiped = True
    try:
        with wrapped_password.revealed() as check_passwd:
            # Did not hit an exception!
            wiped = False
    except:
        wiped = True
    assert wiped, "Single use password cannot be revealed after hashing."
    print("[*] Subprocess memory completely reclaimed by the OS.\n")
    
    # Re-instantiating buffer for verification testing
    verify_buffer = bytearray(b"MyUltraSecurePassword2026!")
    wrapped_password = SingleUse(verify_buffer)
    print(f"Verification Buffer after checking (wiped): {list(verify_buffer)}") # All zeroes
    print("[*] Verifying with correct bytearray...")
    correct_check = subprocess_verify_password(wrapped_password, db_hash)
    print(f"[+] Result: {correct_check}")
    wiped = True
    try:
        with wrapped_password.revealed() as check_passwd:
            # Did not hit an exception!
            wiped = False
    except:
        wiped = True
    assert wiped, "Single use password cannot be revealed after verifying."
