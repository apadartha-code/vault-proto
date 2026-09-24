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

import math
import secrets
import random

import sys
import time
import threading
from typing import Dict, Any

import uuid
import base64

from security.framework import SingleUse, SymmetricKey, EncryptedSecret
from security.aeshelper import SecuredAESGCM, AESCBC
from security.utils import derive_key
from crypto import TransCrypter
from keymaker_ui import KeymakerSession, KeymakerSessionsImpl, KeymakerSessions

class SessionState:
    NAMESPACE = "App"
    # Object keys
    PRIMARY_ENCODING = "encoding1"
    SECONDARY_ENCODING = "encoding2"
    VAULT_ID = "vaultid"
    NO_OTP_TILL = "next_otp_after" # Timestamp in seconds.
    VALIDITY = "valid_till" # Timestamp in seconds.
    READONLY = "readonly"
    
    def __init__(self, master_key_store: SymmetricKey):
        self._transcrypter = None
        self._master_key_store = master_key_store
        self._obj_store = {}
        self._ts = time.time()
        self._lock = threading.Lock()

    def _touch(self):
        self._ts = time.time()

    def set_transcrypter(self, tc: TransCrypter):
        self._touch()
        exists = False
        with self._lock:
            if self._transcrypter is not None:
                exists = True
            else:
                self._transcrypter = tc

        if exists:
            raise AttributeError("Transcrypter can only be set once per session.")

    def get_transcrypter(self) -> TransCrypter:
        self._touch()
        
        transcrypter = None
        with self._lock:
            transcrypter = self._transcrypter

        if not transcrypter:
            raise ValueError("Transcrypter has not yet been set up.")
        return transcrypter

    def set_obj_sub(self, key: str, orig_obj: Any, is_secret: bool = False):
        self._touch()
        stored_obj = orig_obj
        if is_secret:
            if not isinstance(orig_obj, SingleUse):
                raise TypeError("Can encrypt only SingleUse objects. Current object type for key \"{}\" is: {}".format(key, str(type(orig_obj))))
            stored_obj = EncryptedSecret(self._master_key_store, wrapped_plain = orig_obj)

        with self._lock:
            self._obj_store[key] = stored_obj

    def get_obj_sub(self, key: str, is_secret: bool = False) ->  Any:
        self._touch()
        with self._lock:
            val = self._obj_store.get(key)

        if not val:
            return None

        if is_secret and not isinstance(val, EncryptedSecret):
            raise TypeError("Secret objects should only be of type EncryptedSecret. Current object type is: {}".format(str(type(val))))
        return val

    def has_obj_sub(self, key: str) -> bool:
        with self._lock:
            exists = key in self._obj_store
        return exists

    def _namespaced(self, key: str) -> str:
        return SessionState.NAMESPACE+":"+key

    def set_obj(self, key: str, obj: Any, is_secret: bool = False):
        if not key:
            raise ValueError("Cannot set value for empty key")
        self.set_obj_sub(self._namespaced(key), obj, is_secret)

    def get_obj(self, key: str, is_secret: bool = False) -> Any:
        return self.get_obj_sub(self._namespaced(key), is_secret)

    def has_obj(self, key: str) -> bool:
        return self.has_obj_sub(self._namespaced(key))

    def del_obj(self, key: str):
        if self.has_obj(key):
            with self._lock:
                del self._obj_store[self._namespaced(key)]


class KMSessionIface(KeymakerSession):
    def __init__(self, sessionstate: SessionState):
        self._ss = sessionstate

    def _tc(self):
        return self._ss.get_transcrypter()

    def _namespaced(self, strval: str) -> str:
        return "Keymaker:"+strval

    # ==========================================
    # Transcoder interfaces:
    # ==========================================
    # 1. BASE PAIR (Bytes <-> Base64)
    # ==========================================

    def encode(self, raw_bytes: bytes) -> str:
        if isinstance(raw_bytes, bytearray) is False:
            print("WARNING! Encoding from {} in python defeats the purpose of maintaining in-memory secrecy. Consider using wipeable bytearrays.".format(str(type(raw_bytes))), file = sys.stderr)
        return self._tc().encode(SingleUse(raw_bytes))

    def decode(self, base64_data: str) -> bytes:
        with self._tc().decode(base64_data).revealed() as decoded_bytes:
            result = decrypted_bytes.decode('utf-8')
        if not isinstance(result, bytearray):
            print("WARNING: Decoding to {} in python defeats the purpose of maintaining in-memory secrecy. Consider using wipeable bytearrays.".format(str(type(raw_bytes))), file = sys.stderr)
        return result

    # ==========================================
    # 2. STRING VERSION (String <-> Base64)
    # ==========================================

    def encode_str(self, text: str) -> str:
        return self._tc().encode_str(text)

    def decode_str(self, base64_data: str) -> str:
        return self._tc().decode_str(base64_data)

    # ==========================================
    # 3. OBJECT VERSION (Object <-> Base64)
    # ==========================================

    def encode_obj(self, obj: Any) -> str:
        return self._tc().encode_obj(obj)

    def decode_obj(self, base64_data: str) -> Any:
        return self._tc().decode_obj(base64_data)

    # ==========================================
    # Vault interfaces:
    # ==========================================
    # 1. Special mechanism for final encoding.
    # ==========================================

    def save_encoding(self, encoding: bytearray, masked = False):
        if not isinstance(encoding, bytearray):
            print("WARNING: argument _encoding_ of type {} should be a bytearray instead.".format(str(type(encoding))), file = sys.stderr)
        the_key = SessionState.PRIMARY_ENCODING
        if self._ss.has_obj(SessionState.PRIMARY_ENCODING) or self._ss.has_obj(SessionState.VAULT_ID):
            the_key = SessionState.SECONDARY_ENCODING
        if self._ss.has_obj(the_key):
            raise AttributeError("Cannot overwrite existing encoding key {} for session.".format(the_key))
        self._ss.set_obj(the_key, SingleUse(encoding), is_secret = True)

    def mask(self, data: bytearray) -> bytearray:
        return self._tc().mask(data)

    # ==========================================
    # 2. Actual states to be stored and retrieved.
    # ==========================================

    def save_data(self, key: str, value: bytearray):
        self._ss.set_obj_sub(self._namespaced(key), SingleUse(value), is_secret = True)

    def get_data(self, key: str) -> bytearray:
        with self._ss.get_obj_sub(self._namespaced(key), is_secret = True).get().revealed() as secret_bytes:
            return secret_bytes.copy()

    # ==========================================
    # 3. Temporary objects to be stored and retrieved.
    # ==========================================

    def store_obj(self, key: str, value: Any):
        self._ss.set_obj_sub(self._namespaced(key), value)

    def get_obj(self, key: str) -> Any:
        return self._ss.get_obj_sub(self._namespaced(key))

class Sessions:
    SESSION_KEY = "session_id"
    DEFAULT_OTP_LENGTH = 6
    # If we use alphanumeric case insensitive, we have
    # 36 symbols, which is 2^5.16992.. So, with a 6
    # character OTP string, our bit strength < 6 * 5.17
    DEFAULT_OTP_BITS = 31
    OTP_EXPIRY = 30 # seconds
    DEFAULT_SESS_DURATION = 900 # seconds

    # Session types:
    SESSION_TYPE = "session_type"
    SESS_TYPE_ADMIN = "admin"
    SESS_TYPE_API = "api"
    
    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()
        self._master_key_store = None
        self._pending_otps = {}

        # Fixed to lowercase alphanumeric collection (a-z, 0-9)
        self._otp_char_bytes = b"abcdefghijklmnopqrstuvwxyz0123456789"

    def set_master_key(self, master_key):
        if not master_key:
            raise ValueError("Invalid value for master key.")
        if self._master_key_store:
            raise AttributeError("Master key can only be set once.")
        with self._lock:
            self._master_key_store = master_key

    def new(self, session_type):
        if not self._master_key_store:
            raise AttributeError("Master key has not been set.")
        if session_type not in [ Sessions.SESS_TYPE_ADMIN, Sessions.SESS_TYPE_API ]:
            raise ValueError("Unknown session type {}".format(session_type))
        with self._lock:
            session_id = uuid.uuid4().hex
            session_state = SessionState(self._master_key_store)
            session_state.set_obj(Sessions.SESSION_TYPE, session_type)
            self._sessions[session_id] = session_state
        return session_id

    def get(self, session_id):
        with self._lock:
            return self._sessions.get(session_id)

    def purge(self, session_id):
        with self._lock:
            try:
                del self._sessions[session_id]
            except:
                pass

    def __otp_gen(self, length):
        """Return a random alphanumeric (lowercase) bytearray and it's bit strength"""
        alphabet_size = len(self._otp_char_bytes)

        # Generate the bytearray directly using integer indexing on a bytes object
        return bytearray(self._otp_char_bytes[secrets.randbelow(alphabet_size)] for _ in range(length))

    def new_otp(self,
                admin_session_id,
                new_session_expiry,
                otp_expiry = OTP_EXPIRY,
                length = DEFAULT_OTP_LENGTH,
                bit_strength = DEFAULT_OTP_BITS,
                readonly = True
               ):
        admin_session = self.get(admin_session_id)
        if not admin_session:
            raise ValueError("Invalid session id {}".format(session_id))
        if admin_session.get_obj(Sessions.SESSION_TYPE) != Sessions.SESS_TYPE_ADMIN:
            raise AttributeError("Non admin sessions cannot generate OTP.")
        if otp_expiry < 0:
            raise ValueError("OTP expiry cannot be negative.")
        if length <= 0:
            raise ValueError("String length must be greater than zero.")
        if bit_strength < 0:
            raise ValueError("Bit strength cannot be negative.")

        now = time.time()
        if admin_session.has_obj(SessionState.NO_OTP_TILL):
            # Are we inside a blackout of the previous OTP?
            if admin_session.get_obj(SessionState.NO_OTP_TILL) > now:
                raise RuntimeError("OTP generation is temporarily disabled. Try again after some time.")

        # Maximum possible entropy (in bits) for the given length and alphabet size
        strength = length * math.log2(len(self._otp_char_bytes))
        if bit_strength > strength:
            raise ValueError(
                f"Requested bit strength ({bit_strength} bits) exceeds the maximum "
                f"possible entropy ({strength:.2f} bits) for a string of length {length} "
                f"using a lowercase alphanumeric alphabet of size {alphabet_size}."
            )
        otp = self.__otp_gen(length)

        # Save the OTP with otp expiry and session expiry timestamps.
        encrypted_otp = EncryptedSecret(self._master_key_store, wrapped_plain = SingleUse(otp))
        md5_hash = encrypted_otp.md5()
        md5_str = base64.urlsafe_b64encode(encrypted_otp.md5()).decode("utf-8")
        collision = False
        with self._lock:
            if self._pending_otps.get(md5_str):
                ## Oops! The random chance of this happening is too low,
                # so something is almost surely wrong! Crash out!
                collision = True
            else:
                deadline = now + otp_expiry
                self._pending_otps[md5_str] = {
                    'otp': encrypted_otp,
                    'expiry': deadline,
                    'generator': admin_session_id,
                    'session_duration': new_session_expiry,
                    'readonly': readonly,
                    'requested': False # Track if the session request for this OTP has been received.
                }
                admin_session.set_obj(SessionState.NO_OTP_TILL, deadline)

        if collision:
            raise AttributeError("Random hash collision on generated OTP! Something is very likely to be wrong!")

        return encrypted_otp.get()

    def new_app_session(self, otp_hash, challenge_salt_b64):
        otp_data = self._pending_otps.get(otp_hash)
        if not otp_data:
            return { "error": "OTP does not exist." }
        with self._lock:
            if otp_data['requested'] is True:
                # Reject duplicate request.
                return { "error": "OTP reuse." }
            otp_data['requested'] = True
        if otp_data['expiry'] < time.time():
            del self._pending_otps[otp_hash]
            return { "error": "OTP expired" }

        # Go ahead and set up the session and respond with the secret.
        # First, get the vault id from the requesting session and
        # unblock it from generating new OTP.
        generator_session_id = otp_data['generator']
        generator_session = self.get(generator_session_id)
        if not generator_session:
            # Generator session is gone, so let's not go ahead with this connect.
            del self._pending_otps[otp_hash]
            return { "error": "Unknown OTP origin." }
        if not generator_session.has_obj(SessionState.VAULT_ID):
            # Strange! Something must have gone wrong.
            return { "error": "Invalid OTP origin." }
        vault_id = generator_session.get_obj(SessionState.VAULT_ID)
        generator_session.del_obj(SessionState.NO_OTP_TILL)

        # Create the new session ID:
        app_session_id = self.new(Sessions.SESS_TYPE_API)

        # Save the session data...
        app_session = self.get(app_session_id)
        app_session.set_obj(SessionState.VAULT_ID, vault_id)
        app_session.set_obj(SessionState.VALIDITY, otp_data['session_duration'] + time.time())
        app_session.set_obj(SessionState.READONLY, otp_data['readonly'] is True)
        del self._pending_otps[otp_hash]

        # Send back the challenge response.
        # TBD: The right place for handling the common challenge protocol
        # is in the app itself, not here.
        aesalgo = AESCBC()
        plaintext = app_session_id
        try:
            salt = base64.b64decode(challenge_salt_b64)
            session_secret = SecuredAESGCM.random(self._master_key_store)
            with derive_key(otp_data['otp'].get(), salt).revealed() as derived_key:
                cipherbytes = aesalgo.encrypt(derived_key, SingleUse(bytearray(plaintext.encode())))
                cipherbytes2 = aesalgo.encrypt(derived_key, session_secret.get())
            # Create a TransCrypter and attach it to the session for encrypting params.
            encoding_helper = TransCrypter(session_secret, mask_seed = random.randint(0, 2**64))
            # For communicating with the frontend and saving the final encoding.
            self.get(app_session_id).set_transcrypter(encoding_helper)

            return {
                "iv": base64.b64encode(cipherbytes[:16]).decode('utf-8'),
                "ciphertext": base64.b64encode(cipherbytes[16:]).decode('utf-8'),
                "iv2": base64.b64encode(cipherbytes2[:16]).decode('utf-8'),
                "ciphertext2": base64.b64encode(cipherbytes2[16:]).decode('utf-8'),
                "plaintext": plaintext
            }
        except Exception as e:
            print("Error:", str(e), file = sys.stderr)
            return { "error": "Processing failed" }

class KMSessionsIface(KeymakerSessionsImpl):
    def __init__(self, sessions):
        self._sessions = sessions

    def get_session(self, session_id: str) -> KeymakerSession:
        real_sessionstate = self._sessions.get(session_id)
        if real_sessionstate:
            keymaker_session = KMSessionIface(real_sessionstate)
            if keymaker_session is None:
                raise ValueError("Failed to instantiate KeymakerSession for session {}".format(session_id))
            return keymaker_session
        raise KeyError("Session {} does not exist!".format(session_id))
