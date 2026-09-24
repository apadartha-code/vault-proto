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
import sys
import termios
import ctypes
import ctypes.util
import mmap
import resource

import traceback

import abc
import json
import base64
from contextlib import contextmanager
from typing import Any, Generator

import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from security.framework import EncryptedSecret, SingleUse
from security.aeshelper import AESCBC, AESGCM
from security.obfuscate import KeyObfuscator


def read_password_via_syscall(prompt: str = "Enter Secret: ") -> bytearray:
    """
    Disables TTY echo and reads input directly from the raw file descriptor 
    using the OS read system call, bypassing all Python/libc IO buffers.
    """
    sys.stderr.write(prompt)
    sys.stderr.flush()

    # File descriptor 0 is raw standard input
    fd = 0 
    
    # Save and modify terminal flags to strip ECHO
    old_settings = termios.tcgetattr(fd)
    new_settings = termios.tcgetattr(fd)
    new_settings[3] = new_settings[3] & ~termios.ECHO # index 3 is lflags

    password_buffer = bytearray()

    try:
        termios.tcsetattr(fd, termios.TCSANOW, new_settings)
        
        while True:
            # Execute a direct read(2) system call fetching exactly 1 byte
            char_byte = os.read(fd, 1)
            
            if not char_byte or char_byte == b'\n' or char_byte == b'\r':
                break
                
            password_buffer.extend(char_byte)
            
    finally:
        # Guarantee terminal recovery
        termios.tcsetattr(fd, termios.TCSANOW, old_settings)
        sys.stderr.write('\n')
        sys.stderr.flush()

    return SingleUse(password_buffer)


def read_secret_from_fifo(fifo_path: str, prompt: str = "Waiting for FIFO input... ") -> bytearray:
    """
    Opens a named pipe (FIFO) and reads input directly into a mutable bytearray
    using low-level OS read system calls, bypassing Python/libc IO buffers.
    """
    sys.stderr.write(prompt)
    sys.stderr.flush()

    fd = None
    secret_buffer = bytearray()

    try:
        # This os.open call will BLOCK until a writer opens the other end of the FIFO
        fd = os.open(fifo_path, os.O_RDONLY)

        while True:
            # Execute a direct read(2) system call fetching exactly 1 byte
            char_byte = os.read(fd, 1)

            # Break on EOF (writer closed pipe) or newline characters
            if not char_byte or char_byte == b'\n' or char_byte == b'\r':
                break

            secret_buffer.extend(char_byte)

    finally:
        # Always guarantee the file descriptor is released
        if fd is not None:
            os.close(fd)

        sys.stderr.write('\n')
        sys.stderr.flush()

    return SingleUse(secret_buffer)


# TBD: Deprecate xor_mask_data in favour of XorMask class in security/framework
def xor_mask_data(data: bytearray, key_seed: int) -> bytearray:
    """Applies an in-place XOR mask to flatten the entropy signature."""
    state = key_seed
    masked = bytearray(len(data))
    for i in range(len(data)):
        state = (1103515245 * state + 12345) & 0x7fffffff
        mask_byte = (state >> 16) & 0xFF
        masked[i] = data[i] ^ mask_byte
    return masked


def mutable_urandom(bytecount: int) -> bytearray:
    """Because... os.urandom output cannot be explicitly zeroed!"""
    return xor_mask_data(bytearray(os.urandom(bytecount)), secrets.randbelow(2**64))


class BaseAppTranscoder(abc.ABC):
    """
    This class instantiates the encoding / decoding primitives
    expected by the blueprint in the backend that complement the
    corresponding front-end primitives, bot supplied by the
    main app. In our case, the main objective of the encoding /
    decoding is to securely transport the user inputs to the
    blueprint in a manner that does not get dumped at edge firewalls
    or can be scanned from the server's memory.
    """
    def __init__(self, rules: Any = None):
        self.rules = rules

    @abc.abstractmethod
    def _get_key(self) -> SymmetricKey:
        """
        Must be implemented by the derived class.
        Should return a fresh or mutable bytearray holding the AES key.
        """
        raise NotImplementedError("You must implement _get_key() in your subclass.")

    # ==========================================
    # 1. BASE PAIR (Bytes <-> Base64)
    # ==========================================

    def encode(self, wrapped_bytes: SingleUse) -> str:
        combined_buffer = self._get_key().encrypt(wrapped_bytes)
        # The key material only lives on inside the C-level OpenSSL cipher structure now.
        return base64.b64encode(combined_buffer).decode('utf-8')

    def decode(self, base64_data: str) -> SingleUse:
        # 1. Convert the input Base64 string back into raw bytes
        combined_buffer = base64.b64decode(base64_data)
        return self._get_key().decrypt(combined_buffer)

    # ==========================================
    # 2. STRING VERSION (String <-> Base64)
    # ==========================================

    def encode_str(self, text: str) -> str:
        print("WARNING: Encoding from immutable python strings defeats the purpose of maintaining in-memory secrecy. Consider using wipeable bytearrays.", file = sys.stderr)
        raw_bytes = text.encode('utf-8')
        return self.encode(SingleUse(raw_bytes))

    def decode_str(self, base64_data: str) -> str:
        print("WARNING: Decoding to immutable python strings defeats the purpose of maintaining in-memory secrecy. Consider using wipeable bytearrays.", file = sys.stderr)
        with self.decode(base64_data).revealed() as decrypted_bytes:
            return decrypted_bytes.decode('utf-8')

    # ==========================================
    # 3. OBJECT VERSION (Object <-> Base64)
    # ==========================================

    def encode_obj(self, obj: Any) -> str:
        json_string = json.dumps(obj)
        return self.encode_str(json_string)

    def decode_obj(self, base64_data: str) -> Any:
        json_string = self.decode_str(base64_data)
        if not json_string:
            return None

        try:
            return json.loads(json_string)
        except json.JSONDecodeError:
            return None


class TransCrypter(BaseAppTranscoder):
    def __init__(self, session_secret: SymmetricKey, mask_seed = 42):
        super().__init__(rules=None)
        self._mask_seed = mask_seed
        self._encrypted_fe_secret = session_secret

    # TBD: Document where the mask is being used...
    # It was originally introduced with the plan of masking
    # all of the keymaker ingredients.
    def mask(self, data: bytearray) -> bytearray:
        return xor_mask_data(data, self._mask_seed)

    def _get_key(self) -> SymmetricKey:
        return self._encrypted_fe_secret
