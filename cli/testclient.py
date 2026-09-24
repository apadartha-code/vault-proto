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

import argparse
import base64
import getpass
import hashlib
import os
import requests
import urllib3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from cmdloop import run_vault_repl

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts AES-CBC ciphertext and strips PKCS7 padding.
    """
    # 1. Initialize the AES-CBC cipher context
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # 2. Decrypt the raw ciphertext bytes
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 3. Initialize the PKCS7 unpadder (AES block size is 128 bits / 16 bytes)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    
    # 4. Strip the padding and return the raw plaintext bytes
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def main():
    # 1. Parse command line arguments
    parser = argparse.ArgumentParser(description="OTP Authentication and Decryption Client")
    parser.add_argument("hostname", type=str, help="Target server hostname")
    parser.add_argument("port", type=int, help="Target server port")
    parser.add_argument(
        "--verify-cert",
        action="store_true",
        default=False,
        help="Verify SSL certificate (default: False)"
    )
    parser.add_argument(
        "-f",
        "--command-file",
        type=str,
        default=None,
        help="Run commands line by line from a file."
    )
    args = parser.parse_args()

    # 2. Block on OTP input and calculate base64 of MD5 signature
    otp = getpass.getpass("Enter OTP: ")
    md5_hash = hashlib.md5(otp.encode('utf-8')).digest()
    b64_md5_otp = base64.urlsafe_b64encode(md5_hash).decode('utf-8')

    # 3. Generate salt and derive 32-byte AES key using PBKDF2HMAC
    salt = os.urandom(16)
    b64_salt = base64.b64encode(salt).decode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    aes_key = kdf.derive(otp.encode('utf-8'))

    # 4. Make HTTPS POST request
    url = f"https://{args.hostname}:{args.port}/api/otp/{b64_md5_otp}"
    payload = {'salt': b64_salt}

    if not args.verify_cert:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(url, json=payload, verify=args.verify_cert)
        response_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Network error occurred: {e}")
        exit(1)
    except ValueError:
        print("Failed to parse response as JSON.")
        exit(1)

    # 5 & 6. Handle error response
    if "error" in response_data:
        print(f"Error: {response_data['error']}")
        exit(1)

    # 7. Decrypt (iv, ciphertext) pair and compare to plaintext
    try:
        iv = base64.b64decode(response_data['iv'])
        ciphertext = base64.b64decode(response_data['ciphertext'])
        server_plaintext = response_data['plaintext']

        decrypted_bytes = aes_cbc_decrypt(aes_key, iv, ciphertext)
        decrypted_text = decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Failed to decrypt or verify primary payload: {e}")
        exit(1)

    if decrypted_text != server_plaintext:
        print(f"ERROR: Decrypted session id \"{decrypted_text}\" did not match the plaintext \"{server_plaintext}\"")
        exit(1)

    # 8. Decrypt (iv2, ciphertext2) pair to a bytearray
    try:
        iv2 = base64.b64decode(response_data['iv2'])
        ciphertext2 = base64.b64decode(response_data['ciphertext2'])

        decrypted_secret_bytes = aes_cbc_decrypt(aes_key, iv2, ciphertext2)
        # received_secret = bytearray(decrypted_secret_bytes)
        # print(f"Received Secret:     {received_secret}")
    except Exception as e:
        print(f"Failed to decrypt secondary payload (secret): {e}")
        exit(1)

    # 9. Run the command loop.
    endpoint_url = f"https://{args.hostname}:{args.port}/api/vault"
    run_vault_repl(
        server_plaintext,
        decrypted_secret_bytes,
        endpoint_url = endpoint_url,
        verify_cert = args.verify_cert,
        cmd_file = args.command_file
    )

    # 9. Exit
    exit(0)


if __name__ == '__main__':
    main()