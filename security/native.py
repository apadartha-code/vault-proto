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

import ctypes
import ctypes.util

# Load the system's native OpenSSL library
libcrypto_path = ctypes.util.find_library("crypto")
if not libcrypto_path:
    raise ImportError("Could not find system OpenSSL library (libcrypto).")
libcrypto = ctypes.CDLL(libcrypto_path)

# Configure the exact C-argument signatures for OpenSSL's EVP API
# We enforce that all inputs/outputs are treated as direct mutable C-buffers
libcrypto.EVP_MD_CTX_new.restype = ctypes.c_void_p
libcrypto.EVP_sha256.restype = ctypes.c_void_p

libcrypto.EVP_DigestInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
libcrypto.EVP_DigestUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
libcrypto.EVP_DigestFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
libcrypto.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]

def mutable_sha256(key_mutable: bytearray) -> bytearray:
    """
    Generates a 32-byte SHA 256 using an OpenSSL C-buffer.
    Ensure no immutable bytes objects are allocated for the hash.
    Caller is responsible for clearing the resulting hash buffer.
    """
    # Create the mutable bytearray where OpenSSL will write the 32-byte digest
    hash_mutable = bytearray(32)
    
    # Initialize the pointer to the underlying memory of our bytearray
    hash_buffer_ptr = (ctypes.c_char * 32).from_buffer(hash_mutable)
    key_buffer_ptr = (ctypes.c_char * len(key_mutable)).from_buffer(key_mutable)
    
    # Allocate the OpenSSL Digest Context structure in C-memory
    ctx = libcrypto.EVP_MD_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to allocate OpenSSL digest context.")
        
    try:
        # Run SHA-256 inside OpenSSL
        libcrypto.EVP_DigestInit_ex(ctx, libcrypto.EVP_sha256(), None)
        libcrypto.EVP_DigestUpdate(ctx, key_buffer_ptr, len(key_mutable))
        
        # OpenSSL writes the 32-byte hash directly into our mutable bytearray
        libcrypto.EVP_DigestFinal_ex(ctx, hash_buffer_ptr, None)
    finally:
        # Free the C-level structural context
        libcrypto.EVP_MD_CTX_free(ctx)

    return hash_mutable


# Define the low-level OpenSSL one-shot MD5 function signature
# unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
libcrypto.MD5.argtypes = [
    ctypes.c_void_p,       # Data pointer input
    ctypes.c_size_t,       # Data length
    ctypes.c_void_p        # Output digest buffer pointer
]
libcrypto.MD5.restype = ctypes.c_void_p

def mutable_md5(input_data: bytearray) -> bytearray:
    # Pre-allocate exactly 16 bytes for the MD5 digest
    digest_buffer = bytearray(16)
    
    # Get low-level C-pointers to the underlying memory of both arrays
    input_ptr = (ctypes.c_ubyte * len(input_data)).from_buffer(input_data)
    digest_ptr = (ctypes.c_ubyte * 16).from_buffer(digest_buffer)
    
    # Execute the hashing operation directly into the digest_buffer
    libcrypto.MD5(input_ptr, len(input_data), digest_ptr)
    
    return digest_buffer
