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

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from security.framework import SingleUse

def derive_key(wrapped_password: SingleUse, salt: bytes, iterations: int = 100_000) -> SingleUse:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    # 1. Pre-allocate a safe, mutable bytearray container for the key
    derived_key_buffer = bytearray(32)
    
    # 2. Derive directly INTO the mutable buffer (no read-only bytes created)
    with wrapped_password.revealed() as password:
        kdf.derive_into(password, derived_key_buffer)
    
    # Return the mutable bytearray to the context block
    return SingleUse(derived_key_buffer)