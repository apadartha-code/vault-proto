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
import cmd
import getpass
import json
import os
import random
import shlex
import string
import sys
import ssl
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import pyperclip
except ImportError:
    pyperclip = None  # Fallback gracefully if pyperclip is missing


# =====================================================================
# Pluggable Secret Generators
# =====================================================================

def generate_bytes_secret(length: int) -> bytes:
    """Generates random secure bytes."""
    return os.urandom(length)


def generate_standard_secret(length: int) -> bytes:
    """Generates a typical string (letters + digits + punctuation) and encodes to bytes."""
    chars = string.ascii_letters + string.digits + string.punctuation
    secret_str = "".join(random.choice(chars) for _ in range(length))
    return secret_str.encode("utf-8")


# Extensible strategy registry
SECRET_GENERATORS: Dict[str, Callable[[int], bytes]] = {
    "bytes": generate_bytes_secret,
    "standard": generate_standard_secret,
}


def register_secret_generator(name: str, func: Callable[[int], bytes]) -> None:
    """Utility to plug in custom secret generation policies."""
    SECRET_GENERATORS[name] = func


# =====================================================================
# Argparse Setup Helper
# =====================================================================

class NonExitingArgumentParser(argparse.ArgumentParser):
    """Custom parser to prevent argparse from calling sys.exit on error/--help."""
    def error(self, message: str) -> None:
        print(f"Error: {message}")
        raise SystemExit()


def create_parsers() -> Dict[str, argparse.ArgumentParser]:
    parsers = {}

    # 1. ADD
    p_add = NonExitingArgumentParser(prog="add", add_help=True,
                                     description="Add a new key and secret with an optional description.")
    p_add.add_argument("key", type=str, help="Vault key name (max 256 chars)")
    p_add.add_argument("-d", "--description", type=str, default="", help="Key description")
    p_add.add_argument("--default-description", action="store_true", default=True, help="Inherit description from key name")
    p_add.add_argument("--auto-generate", choices=list(SECRET_GENERATORS.keys()), default=None, help="Policy for secret auto-generation")
    p_add.add_argument("--auto-generate-length", type=int, default=8, help="Length for auto-generated secret (min 8)")
    p_add.add_argument("--show-secret", action="store_true", default=False, help="Display entered/generated secret in console")
    parsers["add"] = p_add

    # 2. FIND
    p_find = NonExitingArgumentParser(prog="find", add_help=True,
                                      description="Query for keys by relevance.")
    p_find.add_argument("query", type=str, help="Search query string (2-256 chars)")
    p_find.add_argument("-c", "--count", type=int, default=5, help="Max entries to return (min 1)")
    parsers["find"] = p_find

    # 3. VERSIONS
    p_ver = NonExitingArgumentParser(prog="versions", add_help=True,
                                     description="Get version history for a key.")
    p_ver.add_argument("key", type=str, help="Vault key name")
    parsers["versions"] = p_ver

    # 4. GET
    p_get = NonExitingArgumentParser(prog="get", add_help=True,
                                     description="Query specific key metadata without revealing the secret.")
    p_get.add_argument("key", type=str, help="Vault key name")
    p_get.add_argument("-v", "--version", type=int, default=-1, help="Version number (-1 for latest)")
    parsers["get"] = p_get

    # 5. SECRET
    p_sec = NonExitingArgumentParser(prog="secret", add_help=True,
                                     description="Gets decrypted secret and copies to clipboard.")
    p_sec.add_argument("key", type=str, help="Vault key name")
    p_sec.add_argument("-v", "--version", type=int, default=-1, help="Version number (-1 for latest)")
    p_sec.add_argument("--show-secret", action="store_true", default=False, help="Print secret to standard output")
    parsers["secret"] = p_sec

    # 6. UPDATE
    p_upd = NonExitingArgumentParser(prog="update", add_help=True,
                                     description="Update secret/description for an existing key.")
    p_upd.add_argument("key", type=str, help="Vault key name")
    p_upd.add_argument("-d", "--description", type=str, default="", help="Updated description")
    p_upd.add_argument("--default-description", action="store_true", default=True, help="Inherit description from key name")
    p_upd.add_argument("--add-missing", action="store_true", default=True, help="Add key if missing")
    p_upd.add_argument("--auto-generate", choices=list(SECRET_GENERATORS.keys()), default=None, help="Policy for secret auto-generation")
    p_upd.add_argument("--auto-generate-length", type=int, default=8, help="Length for auto-generated secret (min 8)")
    p_upd.add_argument("--show-secret", action="store_true", default=False, help="Display entered/generated secret in console")
    parsers["update"] = p_upd

    # 7. DELETE
    p_del = NonExitingArgumentParser(prog="delete", add_help=True,
                                     description="Delete a key version or all versions.")
    p_del.add_argument("key", type=str, help="Vault key name")
    p_del.add_argument("-v", "--version", type=int, default=None, help="Specific version to delete")
    p_del.add_argument("--all-versions", action="store_true", default=False, help="Delete all versions of the key")
    parsers["delete"] = p_del

    return parsers


# =====================================================================
# Encryption and decryption of secrets.
# =====================================================================

def encrypt_payload(aesgcm_client: AESGCM, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AESGCM.
    Generates a random 12-byte IV and prepends it to the final ciphertext.
    """
    # 1. Generate a secure, random 12-byte IV (Standard for AES-GCM)
    iv = os.urandom(12)
    
    # 2. Encrypt the plaintext (passing None for Associated Data)
    ciphertext = aesgcm_client.encrypt(iv, plaintext, None)
    
    # 3. Prepend the IV to the ciphertext and return as a single bytes object
    return iv + ciphertext


def decrypt_payload(aesgcm_client: AESGCM, iv_and_ciphertext: bytes) -> bytes:
    """
    Decrypts a combined bytes payload.
    Extracts the first 12 bytes as the IV and decrypts the remaining ciphertext.
    """
    # 1. Slice out the 12-byte IV from the front of the payload
    iv = iv_and_ciphertext[:12]
    ciphertext = iv_and_ciphertext[12:]
    
    # 2. Decrypt the remaining ciphertext using the extracted IV
    return aesgcm_client.decrypt(iv, ciphertext, None)



# =====================================================================
# Main REPL Shell Class
# =====================================================================

class VaultCLI(cmd.Cmd):
    intro = "Vault REPL Shell initialized. Type 'help' or '?' to list commands."
    prompt = "vault> "

    def __init__(self, session_id: str, aes_key: bytes, endpoint_url: str = "http://localhost:8080/api/vault", verify_cert = True):
        super().__init__()
        self.session_id = session_id
        self.__aesgcm = AESGCM(aes_key)
        self.endpoint_url = endpoint_url
        self.verify_cert = verify_cert
        self.parsers = create_parsers()
        self.key_buffer: List[str] = []  # Dynamic key tab-completion buffer

    # --- Helper Methods ---

    def _register_key(self, key: str) -> None:
        """Appends a key to the completion buffer if not already present."""
        if key and key not in self.key_buffer:
            self.key_buffer.append(key)

    def _call_backend(self, operation: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Encodes request, posts to /api/vault, and parses response."""
        # encoded_session_id = base64.b64encode(self.session_id.encode("utf-8")).decode("utf-8")
        payload = {
            "session-id": self.session_id, # encoded_session_id,
            "operation": operation,
            "arguments": arguments,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint_url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            if not self.verify_cert:
                ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, context=ctx) as resp:
                    resp_data = resp.read().decode("utf-8")
                    return json.loads(resp_data)
            else:
                with urllib.request.urlopen(req) as resp:
                    resp_data = resp.read().decode("utf-8")
                    return json.loads(resp_data)
        except urllib.error.URLError as e:
            print(f"[Backend Error] Failed to connect: {e}")
            return None
        except json.JSONDecodeError:
            print("[Backend Error] Failed to parse JSON response from backend.")
            return None

    def _process_secret_input(self, auto_gen: Optional[str], length: int, show_secret: bool) -> bytes:
        """Handles secret prompt or auto-generation logic."""
        if auto_gen:
            if length < 8:
                print("Warning: auto-generate-length must be at least 8. Enforcing min length=8.")
                length = 8
            generator_fn = SECRET_GENERATORS.get(auto_gen, generate_standard_secret)
            secret_bytes = generator_fn(length)
        else:
            prompt_str = getpass.getpass("Enter Secret: ")
            secret_bytes = prompt_str.encode("utf-8")

        if show_secret:
            try:
                print(f"[Secret Output]: {secret_bytes.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"[Secret Output (Hex)]: {secret_bytes.hex()}")

        return secret_bytes

    def complete_key_arg(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Generic tab-completion provider for 'key' parameter across operations."""
        if not text:
            return self.key_buffer
        return [k for k in self.key_buffer if k.startswith(text)]

    # Dynamic completion bindings for commands taking 'key' as 1st positional arg
    complete_add = complete_key_arg
    complete_versions = complete_key_arg
    complete_get = complete_key_arg
    complete_secret = complete_key_arg
    complete_update = complete_key_arg
    complete_delete = complete_key_arg

    # --- Commands implementation ---

    def do_add(self, arg: str) -> None:
        """Add a new key and secret."""
        try:
            args = self.parsers["add"].parse_args(shlex.split(arg))
            if len(args.key) > 256:
                print("Error: key length exceeds 256 characters.")
                return

            secret_bytes = self._process_secret_input(
                args.auto_generate, args.auto_generate_length, args.show_secret
            )
            secret_secret = encrypt_payload(self.__aesgcm, secret_bytes)
            secret_b64 = base64.b64encode(secret_secret).decode("utf-8")

            payload = {
                "key": args.key,
                "secret": secret_b64,
                "description": args.description,
                "default-description": args.default_description,
            }

            resp = self._call_backend("add", payload)
            if resp is not None:
                print(json.dumps(resp, indent=2))
                self._register_key(args.key)
        except SystemExit:
            pass

    def do_find(self, arg: str) -> None:
        """Query keys by relevance."""
        try:
            args = self.parsers["find"].parse_args(shlex.split(arg))
            if not (2 <= len(args.query) <= 256):
                print("Error: query length must be between 2 and 256 characters.")
                return
            if args.count < 1:
                print("Error: count must be at least 1.")
                return

            resp = self._call_backend("find", {"query": args.query, "count": args.count})
            if resp is not None:
                print(json.dumps(resp, indent=2))
                # Automatically extract found keys into the completion buffer
                if isinstance(resp, dict) and "keys" in resp and isinstance(resp["keys"], list):
                    for k in resp["keys"]:
                        if isinstance(k, str):
                            self._register_key(k)
        except SystemExit:
            pass

    def do_versions(self, arg: str) -> None:
        """Fetch version history for a key."""
        try:
            args = self.parsers["versions"].parse_args(shlex.split(arg))
            resp = self._call_backend("versions", {"key": args.key})
            if resp is not None:
                print(json.dumps(resp, indent=2))
                self._register_key(args.key)
        except SystemExit:
            pass

    def do_get(self, arg: str) -> None:
        """Get metadata for a specific key."""
        try:
            args = self.parsers["get"].parse_args(shlex.split(arg))
            resp = self._call_backend("get", {"key": args.key, "version": args.version})
            if resp is not None:
                print(json.dumps(resp, indent=2))
                self._register_key(args.key)
        except SystemExit:
            pass

    def do_secret(self, arg: str) -> None:
        """Fetch secret, copy to clipboard, and optionally display."""
        try:
            args = self.parsers["secret"].parse_args(shlex.split(arg))
            resp = self._call_backend("secret", {"key": args.key, "version": args.version})
            if resp is not None:
                self._register_key(args.key)
                # Parse returned b64 secret from payload response structure
                secret_b64 = resp.get("response")
                encrypted_secret = base64.b64decode(secret_b64.encode('utf-8'))
                secret_bytes = decrypt_payload(self.__aesgcm, encrypted_secret)
                try:
                    decoded_secret = secret_bytes.decode('utf-8')
                except Exception:
                    decoded_secret = base64.b64encode(secret_bytes).decode("utf-8")

                if pyperclip:
                    pyperclip.copy(decoded_secret)
                    print("[Notice]: Response secret copied to clipboard.")
                else:
                    print("[Warning]: 'pyperclip' module not installed. Could not copy to clipboard.")

                if args.show_secret:
                    print(f"Secret: {decoded_secret}")
                else:
                    print(json.dumps({k: v for k, v in resp.items() if k != "secret"}, indent=2))
        except SystemExit:
            pass

    def do_update(self, arg: str) -> None:
        """Update an existing key secret or description."""
        try:
            args = self.parsers["update"].parse_args(shlex.split(arg))
            secret_bytes = self._process_secret_input(
                args.auto_generate, args.auto_generate_length, args.show_secret
            )
            secret_secret = encrypt_payload(self.__aesgcm, secret_bytes)
            secret_b64 = base64.b64encode(secret_secret).decode("utf-8")

            payload = {
                "key": args.key,
                "secret": secret_b64,
                "description": args.description,
                "default-description": args.default_description,
                "add-missing": args.add_missing,
            }

            resp = self._call_backend("update", payload)
            if resp is not None:
                print(json.dumps(resp, indent=2))
                self._register_key(args.key)
        except SystemExit:
            pass

    def do_delete(self, arg: str) -> None:
        """Delete a key version or all versions."""
        try:
            args = self.parsers["delete"].parse_args(shlex.split(arg))

            # Command-specific validation requirement
            if args.version is None and not args.all_versions:
                print("Error: Either a specific '--version' must be specified or '--all-versions' enabled.")
                return

            payload = {
                "key": args.key,
                "version": args.version,
                "all-versions": args.all_versions,
            }

            resp = self._call_backend("delete", payload)
            if resp is not None:
                print(json.dumps(resp, indent=2))
        except SystemExit:
            pass

    # --- Loop Termination & Signals ---

    def do_exit(self, arg: str) -> bool:
        """Exit the REPL session."""
        print("Exiting vault CLI session.")
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the REPL session."""
        return self.do_exit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Handles Ctrl+D exit cleanly."""
        print()
        return self.do_exit(arg)

    def emptyline(self) -> None:
        """Prevent repeating the last command on hitting Enter."""
        pass


# =====================================================================
# Main Execution Interface
# =====================================================================

def run_batch(cli: VaultCLI, cmd_file: str) -> None:
    try:
        with open(cmd_file, "r") as f:
            for line in f:
                cmd = line.strip()
                # Skip empty lines and comments
                if cmd and not cmd.startswith("#"):
                    print(f"Running: {cmd}")
                    stop = cli.onecmd(cmd)
                    if stop:
                        break
    except FileNotFoundError as fnfe:
        print("Command script {} not found.".format(cmd_file))

def run_vault_repl(session_id: str,
                   aes_key: bytes,
                   endpoint_url: str = "http://localhost:8080/api/vault",
                   verify_cert = True,
                   cmd_file = None) -> None:
    """Entry point accepting session-id to start the interactive REPL CLI session."""
    cli = VaultCLI(session_id=session_id, aes_key=aes_key, endpoint_url=endpoint_url, verify_cert = verify_cert)

    if cmd_file:
        try:
            run_batch(cli, cmd_file)
        except KeyboardInterrupt:
            # Traps Ctrl+C globally, prevents shell crash, resets prompt
            print("\n[Notice]: Batch operation cancelled.")
    else:
        while True:
            try:
                cli.cmdloop()
                break  # Exit loop when cmdloop returns True
            except KeyboardInterrupt:
                # Traps Ctrl+C globally, prevents shell crash, resets prompt
                print("\n[Notice]: Operation cancelled.")
                continue


if __name__ == "__main__":
    # Dummy main execution harness
    STATIC_SESSION_ID = "dummy session for testing"
    run_vault_repl(session_id=STATIC_SESSION_ID)