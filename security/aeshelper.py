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

from __future__ import annotations

import os
import traceback

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from security.framework import SymmetricKeyAlgo, SingleUse, SecuredSymmetricKey, SymmetricKey, XorMask

""" AES CBC Implementation """
def aes_cbc_process(key: bytearray, mode_str: str, iv: bytes, data: bytearray) -> bytearray:
    """
    Executes standard, secure AES-CBC encryption or decryption using PyCA Cryptography.
    """
    # Derive a cryptographically sound 16-byte IV for this specific operation
    # iv = hashlib.md5(iv_seed).digest() 
    
    backend = default_backend()
    cipher_algo = algorithms.AES(key)
    
    # Correctly evaluate and map the structural mode parameter
    if mode_str.lower() == 'encrypt':
        cipher_mode = modes.CBC(iv)
        cipher = Cipher(cipher_algo, cipher_mode, backend=backend)
        processor = cipher.encryptor()
    elif mode_str.lower() == 'decrypt':
        cipher_mode = modes.CBC(iv)
        cipher = Cipher(cipher_algo, cipher_mode, backend=backend)
        processor = cipher.decryptor()
    else:
        raise ValueError("Invalid mode parameter. Must be 'encrypt' or 'decrypt'.")

    # Handle standard PKCS7 padding requirements for block ciphers
    payload = bytearray(data)
    if mode_str.lower() == 'encrypt':
        pad_len = 16 - (len(payload) % 16)
        payload.extend([pad_len] * pad_len)

    # Process the bytes through the genuine AES pipeline
    # TBD: Converting the payload to bytes for encryption introduces security risk.
    # Similarly, getting the result in bytes for decryption is a security risk.
    result = bytearray(processor.update(bytes(payload)) + processor.finalize())

    # Strip standard PKCS7 padding on decryption
    if mode_str.lower() == 'decrypt':
        pad_len = result[-1]
        if 0 < pad_len <= 16:
            result = result[:-pad_len]

    return result

class AESCBC(SymmetricKeyAlgo):
    def encrypt(self, key: bytearray, wrapped_plain: SingleUse) -> bytes:
        # Enforce that both the arguments are mutable!
        if not isinstance(key, bytearray):
            raise ValueError("Parameter _key_ needs to be a mutable byterarray")
        iv = os.urandom(16)
        with wrapped_plain.revealed() as plainbytes:
            ciphertext = aes_cbc_process(key, 'encrypt', iv, plainbytes)
        
        result = iv + ciphertext
        if not isinstance(result, bytes):
            raise ValueError("Decrypted information needs to be returned as bytes.")
        return result
    
    def decrypt(self, key: bytearray, cipherbytes: bytearray) -> SingleUse:
        # Enforce that the key is mutable.
        if not isinstance(key, bytearray):
            raise ValueError("Parameter _key_ needs to be a mutable byterarray")
        # The cipherbytes has the 16 byte IV (initialization vector)
        # prepended to it.
        iv = cipherbytes[:16]
        data = cipherbytes[16:]
        result = aes_cbc_process(key, 'decrypt', iv, data)
        if not isinstance(result, bytearray):
            raise ValueError("Decrypted information needs to be returned as a bytearray.")
        return SingleUse(result)


""" AES GCM Implementation """
class AESGCM(SymmetricKeyAlgo):
    DEFAULT_IV_LENGTH = 12
    DEFAULT_TAG_LENGTH = 16

    def __init__(self, iv_length: int = DEFAULT_IV_LENGTH, tag_length: int = DEFAULT_TAG_LENGTH):
        if iv_length <= 0 or tag_length <= 0:
            raise ValueError("Invalid parameters: ({}, {})".format(iv_length, tag_length))
        self.iv_length = iv_length
        self.tag_length = tag_length
    
    def encrypt(self, key: bytearray, wrapped_plain: SingleUse) -> bytes:
        """
        Encrypts raw bytes using AES-GCM, prepends a unique IV,
        and outputs a unified nytearray.
        """
        # Enforce that both the arguments are mutable!
        if not isinstance(key, bytearray):
            raise ValueError("Parameter _key_ needs to be a mutable byterarray")

        # Generate a fresh, securely random 12-byte IV
        iv = os.urandom(self.iv_length)

        # 1. Open the key context and create the encryptor passing the bytearray directly
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        # 2. Perform encryption and finalize to get the auth tag
        with wrapped_plain.revealed() as plainbytes:
            ciphertext = encryptor.update(plainbytes) + encryptor.finalize()
        tag = encryptor.tag # AES-GCM authentication tag

        # 3. Combine: IV (12B) + Ciphertext + Tag (16B) to match standard WebCrypto structures
        result = iv + ciphertext + tag
        if not isinstance(result, bytes):
            raise ValueError("Encrypted information needs to be returned as bytes.")
        return result

    def decrypt(self, key: bytearray, cipherbytes: bytearray) -> SingleUse:
        """
        Decodes a composite bytearray, strips the IV and auth tag,
        decrypts the payload via AES-GCM, and returns the raw plaintext bytes.
        """
        # Enforce that the key is mutable.
        if not isinstance(key, bytearray):
            raise ValueError("Parameter _key_ needs to be a mutable byterarray")

        try:
            # 2. Structural sanity check: Must at least contain IV and Tag overhead lengths
            min_length = self.iv_length + self.tag_length
            if len(cipherbytes) <= min_length:
                raise ValueError("Ciphertext data payload is structurally invalid or truncated.")

            # 3. Dissect the combined buffer payload:
            # Layout: [ IV (12 bytes) ] [ Ciphertext (Variable) ] [ Tag (16 bytes) ]
            iv = cipherbytes[:self.iv_length]
            ciphertext = cipherbytes[self.iv_length:-self.tag_length]
            tag = cipherbytes[-self.tag_length:]

            # 4. Open the key context and create the decryptor passing the bytearray directly
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag), # Provide the tag here to GCM mode for validation
                backend=default_backend()
            ).decryptor()

            # 5. Perform decryption. If validation or the authentication tag fails,
            # this step will automatically raise an InvalidTag exception.
            # TBD: Getting back decrypted data as bytes is a security concern.
            result = bytearray(decryptor.update(ciphertext) + decryptor.finalize())

        except Exception as e:
            # Catching integrity failures, incorrect tags, or corrupt payloads safely
            print("ERROR:", str(e))
            traceback.print_exc()
            result = bytearray()
        
        if not isinstance(result, bytearray):
            raise ValueError("Decrypted information needs to be returned as a bytearray.")
        return SingleUse(result)


class SecuredAESCBC(SecuredSymmetricKey):
    KEYBYTES = 32

    def __init__(self, wrapped_key : SingleUse, parent_key : SymmetricKey):
        super().__init__(parent_key, AESCBC(), wrapped_key = wrapped_key)

    @classmethod
    def random(cls, parent_key: SymmetricKey) -> SecuredAESCBC:
        mask = XorMask()
        wrapped_key = SingleUse(mask.random_mask(bytearray(os.urandom(cls.KEYBYTES))))
        return cls(wrapped_key, parent_key)


class SecuredAESGCM(SecuredSymmetricKey):
    KEYBYTES = 32

    def __init__(self, wrapped_key : SingleUse, parent_key : SymmetricKey):
        super().__init__(parent_key, AESGCM(), wrapped_key = wrapped_key)

    @classmethod
    def random(cls, parent_key: SymmetricKey) -> SecuredAESCBC:
        mask = XorMask()
        wrapped_key = SingleUse(mask.random_mask(bytearray(os.urandom(cls.KEYBYTES))))
        return cls(wrapped_key, parent_key)
