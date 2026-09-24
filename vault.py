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
import time
import random
import string
import json
import base64
import threading

from typing import List, Tuple, Dict, Any

from crypto import mutable_urandom
from search import BM25InMemoryFuzzySearch
from keylockmgr import HierarchicalLockManager
from pwhash import subprocess_hash_password, subprocess_verify_password

from security.native import mutable_sha256
from security.framework import EncryptedSecret, SingleUse
from security.aeshelper import SecuredAESCBC

class VaultRecord:
    RECORD_KEY_KEY    = "key"
    RECORD_KEY_DESC   = "desc"
    RECORD_KEY_SECRET = "secret"
    RECORD_KEY_VER    = "version"
    RECORD_KEY_TIME   = "ts" # Epoch in milliseconds
    
    def __init__(self, data: Dict[str, Any]):
        self.key = str(data[VaultRecord.RECORD_KEY_KEY])
        self.keywords = str(data[VaultRecord.RECORD_KEY_DESC])
        self.encrypted_secret = bytearray(base64.b64decode(data[VaultRecord.RECORD_KEY_SECRET]))
        self.ts = int(data[VaultRecord.RECORD_KEY_TIME])
        self.version = int(data[VaultRecord.RECORD_KEY_VER])

    def as_dict(self):
        data = {
            VaultRecord.RECORD_KEY_KEY: str(self.key),
            VaultRecord.RECORD_KEY_DESC: str(self.keywords),
            VaultRecord.RECORD_KEY_SECRET: base64.b64encode(self.encrypted_secret).decode('utf-8'),
            VaultRecord.RECORD_KEY_VER: int(self.version),
            VaultRecord.RECORD_KEY_TIME: int(self.ts)
        }
        return data

    @classmethod
    def new_record(cls, key: str, secret: bytearray, desc : str = "", version : int = 0) -> VaultRecord:
        if isinstance(desc, str) is False:
            raise TypeError("Parameter _desc_ needs to be a string.")
        
        if isinstance(key, str) is False:
            raise TypeError("Parameter _key_ needs to be a string.")
        if len(key) == 0:
            raise ValueError("Key is empty string.")
        
        # Secret is already encrypted.
        # However, we shall still need it to be a bytearray
        # to ensure that we do the base64 encoding properly.
        data = {
            cls.RECORD_KEY_KEY: key,
            cls.RECORD_KEY_DESC: desc,
            cls.RECORD_KEY_SECRET: base64.b64encode(secret).decode('utf-8'),
            cls.RECORD_KEY_VER: version,
            cls.RECORD_KEY_TIME: int(time.time() * 1000)
        }
        return VaultRecord(data)
    
    def update(self, secret : bytearray) -> VaultRecord:
        # Clone, without changing self.
        return VaultRecord.new_record(self.key, secret, desc = self.keywords, version = self.version + 1)


class Vault:
    # TBD: 1. Field limits, 2. Key count, 3. Checkpoint version and journal file for recovery.
    # TBD: 4. Vault version.
    FINDER_RESOURCE_KEY = "__FINDER_LOCK__"
    SAVER_RESOURCE_KEY = "__FILE_LOCK__"
    LATEST_VERSION = "latest"
    NEXT_VERSION = "next"
    KEYINFO = "keyinfo"
    RECORDS = "records"
    
    def __init__(self, sek: SecuredAESCBC,  keyinfo: Dict[str, Any] = {}, records: List[Dict[str, Any]] = []):
        if isinstance(keyinfo, dict) is False:
            raise ValueError("The argument _keyinfo_ should be a dict.")
        if isinstance(records, list) is False:
            raise ValueError("The argument _records_ should be a list.")
        self._sek = sek # The secret encryption key.
        self._finder = BM25InMemoryFuzzySearch(min_ngram=1, max_ngram=2)
        self._dirty = False
        
        self._lock_manager = HierarchicalLockManager()
        # Just leaving timeouts here ...
        # to remember the capabilities of the lock manager.
        self.read_timeout = None
        self.write_timeout = None
        self.save_timeout = None
        self.finder_timeout = None

        self._lock_manager.persistent_id(self.SAVER_RESOURCE_KEY)
        self._lock_manager.persistent_id(self.FINDER_RESOURCE_KEY)
        self._keyinfo = keyinfo
        self._records = {}
        for record in records:
            vr = VaultRecord(record)
            if vr.key not in self._keyinfo:
                raise ValueError("Record with unknown key {} encountered when initializing vault.".format(vr.key))
            self._add(vr)
    
    @classmethod
    def load(cls, filepath: str, dek: SecuredAESCBC, sek: SecuredAESCBC) -> Vault:
        encrypted_data = None
        with open(filepath, "rb") as vaultfile:
            encrypted_data = bytearray(vaultfile.read())

        # The decrypt function automatically strips off the initial 16 bytes for IV.
        with dek.decrypt(encrypted_data).revealed() as data:
            # Match the checksum of the sek before loading the data.
            seksum_wrap = SingleUse(sek.md5())
            found = SingleUse(data[:16])
            with seksum_wrap.revealed() as seksum:
                with found.revealed() as checksum:
                    seksum_matches = seksum == data[:16]
            if not seksum_matches:
                raise ValueError("MD5 checksum of secret encryption key does not match.")
    
            jsdata = data[16:].decode('utf-8')
        vdata = json.loads(jsdata)
        return cls(sek, vdata[cls.KEYINFO], vdata[cls.RECORDS])

    def _serialize(self):
        records = []
        for key, versions in self._records.items():
            for version, record in versions.items():
                if version != Vault.LATEST_VERSION:
                    records.append(record.as_dict())
        vdata = { Vault.RECORDS: records, Vault.KEYINFO: self._keyinfo }
        return json.dumps(vdata)
    
    def save(self, filepath: str, dek: SecuredAESCBC, overwrite = True):
        """Assign a random timestamp when saving."""
        exists = os.path.isfile(filepath)
        if exists and self._dirty is False:
            return # Nothing to save.

        with self._lock_manager.checkpoint_lock(timeout=self.save_timeout) as acquired:
            if not acquired:
                raise TimeoutError("Could not acquire global checkpoint lock.")
            jsdata = self._serialize()

        # Convert to bytes and encrypt with dek.
        # Prepend the checksum of the secret encryption key (SEK) to the bytes
        # before encrypting. The encrypt function automatically prepends a 16
        # byte IV to the data.
        with SingleUse(self._sek.md5()).revealed() as seksum:
            encrypted_data = dek.encrypt(SingleUse(seksum + bytearray(jsdata, 'utf-8')))
        # Write to the file.
        omode = "wb" if overwrite else "xb"
        with self._lock_manager.exclusive_lock(self.SAVER_RESOURCE_KEY, timeout = self.save_timeout) as acquired2:
            if not acquired:
                raise TimeoutError("Could not acquire global file write lock.")
            with open(filepath, omode) as vaultfile:
                vaultfile.write(encrypted_data)
		
        # Randomize access/modify times to obfuscate updates
        random_time = time.time() - random.randint(1000, 100000)
        os.utime(filepath, (random_time, random_time))

    def _versions(self, key: str) -> Tuple[List[int],int]:
        vers = []
        next_v = 0
        if key in self._keyinfo:
            vers = sorted([ v for v in self._records[key].keys() if type(v) is int ])
            next_v = self._keyinfo[key][Vault.NEXT_VERSION]
        return vers, next_v
        
    def versions(self, key: str) -> Dict[str, Any]:
        if isinstance(key, str) is False:
            raise TypeError("Parameter _key_ needs to be a string.")
        if len(key) == 0:
            raise ValueError("Parameter _key_ cannot be an empty string.")
        with self._lock_manager.read_lock(key, timeout=self.read_timeout) as acquired:
            if not acquired:
                raise TimeoutError(f"Read lock timeout for key: '{key}'")
            vers, next_v = self._versions(key)
        return { 'existing': vers, 'next': next_v }

    def _get(self, key : str, version : int) -> VaultRecord:
        if key not in self._keyinfo:
            raise KeyError("Invalid key {}".format(key))
        ver = version
        if ver < 0:
            ver = self._records[key][Vault.LATEST_VERSION]
        record = self._records[key].get(ver, None)
        if record is None:
            raise KeyError("Record for version {} does not exist.".format(ver))
        return self._records[key][ver]

    def get(self, key : str, version : int = -1) -> VaultRecord:
        if isinstance(version, int) is False:
            raise TypeError("Key version should be of type int.")
            
        with self._lock_manager.read_lock(key, timeout=self.read_timeout) as acquired:
            if not acquired:
                raise TimeoutError(f"Read lock timeout for key: '{key}'")
            return self._get(key, version)

    def secret(self, key : str, version : int = -1) -> SingleUse:
        record = None
        try:
            record = self.get(key, version)
        except KeyError as ke:
            return None
        return self._sek.decrypt(record.encrypted_secret)

    def _add(self, vrecord: VaultRecord):
        if vrecord.key not in self._records:
            # New key!
            self._records[vrecord.key] = { Vault.LATEST_VERSION: -1 }
        if vrecord.version in self._records[vrecord.key]:
            raise ValueError("Version {} for key {} already exists.".format(vrecord.version, vrecord.key))
        self._records[vrecord.key][vrecord.version] = vrecord
        if vrecord.keywords:
            with self._lock_manager.exclusive_lock(self.FINDER_RESOURCE_KEY, timeout = self.finder_timeout):
                self._finder.index_record((vrecord.key, vrecord.version), vrecord.keywords)
        if vrecord.version > self._records[vrecord.key][Vault.LATEST_VERSION]:
            self._records[vrecord.key][Vault.LATEST_VERSION] = vrecord.version
        self._dirty = True

    def _default_desc(self, key):
        try:
            # Get the latest version if exists.
            prev_record = self._get(key, -1)
        except KeyError as ke:
            # Previous record does not exist.
            return key # Make the key the default description.
        if len(prev_record.keywords) > 0:
            return prev_record.keywords
        return key

    def add(self, key : str, wrapped_secret : SingleUse, desc : str = "", default_desc = True):
        if len(wrapped_secret) == 0:
            raise ValueError("Cannot add record with empty secret.")
        encrypted_secret = self._sek.encrypt(wrapped_secret)
        
        with self._lock_manager.write_lock(key, timeout=self.write_timeout) as acquired:
            if not acquired:
                raise TimeoutError(f"Write lock timeout for key: '{key}'")
            if key in self._keyinfo:
                raise KeyError("Key {} already exists.".format(key))
            if len(desc) == 0 and default_desc is True:
                desc = self._default_desc(key)
            self._add(VaultRecord.new_record(key, encrypted_secret, desc = desc))
            # If the add succeeds, add the key info.
            self._keyinfo[key] = { Vault.NEXT_VERSION: 1 }

    def update(self, key : str, wrapped_secret : SingleUse, desc : str = "", add_missing = True, default_desc = True):
        if len(wrapped_secret) == 0:
            raise ValueError("Cannot update record to empty secret.")
        encrypted_secret = self._sek.encrypt(wrapped_secret)
        
        with self._lock_manager.write_lock(key, timeout=self.write_timeout) as acquired:
            if not acquired:
                raise TimeoutError(f"Write lock timeout for key: '{key}'")
            if key not in self._keyinfo:
                if not add_missing:
                    raise KeyError("Non-existent key {} for update.".format(key))
                else:
                    self._keyinfo[key] = { Vault.NEXT_VERSION: 0 }
            if len(desc) == 0 and default_desc is True:
                desc = self._default_desc(key)
            version = self._keyinfo[key][Vault.NEXT_VERSION]
            self._add(VaultRecord.new_record(key, encrypted_secret, desc = desc, version = version))
            # If the update succeeds, update the key info.
            self._keyinfo[key][Vault.NEXT_VERSION] = version + 1

    def _remove(self, key : str, version : int):
        # Ensure that the key exists.
        # It may get removed in a race condition.
        versions = self._records.get(key, None)
        if not versions:
            # Key does not exist.
            return
        # Check that the specific version exists.
        if versions.get(version, None) is None:
            return # Version does not exist.
        
        if version == self._records[key][Vault.LATEST_VERSION]:
            # If we are deleting the latest version, an
            # older version needs to become the latest.
            remaining = [ ver for ver in self._records[key].keys() if ver != version and type(ver) is int ]
            if len(remaining) > 0:
                self._records[key][Vault.LATEST_VERSION] = max(remaining)
            else:
                self._records[key][Vault.LATEST_VERSION] = -1
        
        with self._lock_manager.exclusive_lock(self.FINDER_RESOURCE_KEY, timeout = self.finder_timeout):
            self._finder.drop_record((key, version))
        del self._records[key][version]
        self._dirty = True

    def del_version(self, key: str, version : int):
        if isinstance(version, int) is False:
            raise TypeError("Key version should be of type int.")
            
        with self._lock_manager.write_lock(key, timeout=self.write_timeout) as acquired:
            if not acquired:
                raise TimeoutError(f"Write lock timeout for key: '{key}'")
            if key not in self._keyinfo:
                return # No need to throw tantrums.
            self._remove(key, version)

    def del_key(self, key: str):
        with self._lock_manager.write_lock(key, timeout=self.write_timeout) as acquired:
            if not acquired:
                raise TimeoutError(f"Write lock timeout for key: '{key}'")
            if key not in self._keyinfo:
                return # No need to throw tantrums.
            # Sort the versions in ascending order to remove the latest version last.
            versions = sorted([ v for v in self._records[key].keys() if type(v) is int ])
            for ver in versions:
                # Remove the versions individually to ensure that their indexing
                # are also removed properly.
                self._remove(key, ver)
            del self._records[key]
            del self._keyinfo[key]

    def find(self, query : str, max_count : int = 5) -> List[Tuple[str, int]]:
        """Return the (key, version) tuples in rank order"""
        with self._lock_manager.shared_lock(self.FINDER_RESOURCE_KEY, timeout = self.finder_timeout):
            return [ idx for idx, score in self._finder.search(query, limit = max_count) ]


class VaultMetaKey(SecuredAESCBC):
    def __init__(self, wrapped_key : SingleUse, parent_key : SecuredAESCBC):
        super().__init__(wrapped_key, parent_key)

    def as_storage_id(self) -> str:
        """
        Take the decrypted key and compute a SHA 256,
        then xor the two halves of the hash to get an unique hex string.
        """
        with self.get().revealed() as raw_key:
            temp_val = SingleUse(mutable_sha256(raw_key))

        id = None
        with temp_val.revealed() as keyhash:
            # Calculate the 16-byte Split-and-XOR filename in a clean container
            id_bytes = bytearray(16)
            for i in range(16):
                id_bytes[i] = keyhash[i] ^ keyhash[i + 16]
                
            id = id_bytes.hex()

        return id

    def generate_encrypted_metadata(self, vaultid: str) -> bytearray:
        encrypted_metadata = bytearray()
        dek = SingleUse(mutable_urandom(32)) # Data encryption key for the vault.
        sek = SingleUse(mutable_urandom(32)) # Secret encryption key for the vault.

        with dek.revealed() as dek_bytes:
            with sek.revealed() as sek_bytes:
                encrypted_metadata = self.encrypt(SingleUse(dek_bytes + sek_bytes + vaultid.encode('utf-8')))

        return encrypted_metadata

    def reencrypt_metadata(self, vaultid: str, dek: SecuredAESCBC, sek: SecuredAESCBC) -> bytearray:
        encrypted_metadata = bytearray()
        with self.decrypt(dek.export(self)).revealed() as dek_bytes:
            with self.decrypt(sek.export(self)).revealed() as sek_bytes:
                encrypted_metadata = self.encrypt(SingleUse(dek_bytes + sek_bytes + vaultid.encode('utf-8')))

        return encrypted_metadata

    def decrypt_metadata(self, encrypted_metadata: bytearray) -> Tuple[str, SecuredAESCBC, SecuredAESCBC]:
        with self.decrypt(encrypted_metadata).revealed() as metadata:
            dek = SecuredAESCBC(SingleUse(metadata[:32]), self._key)
            sek = SecuredAESCBC(SingleUse(metadata[32:64]), self._key)
            vaultid_bytes = metadata[64:]
            vaultid = vaultid_bytes.decode('utf-8')

        return (vaultid, dek, sek)


class VaultManager:
    DEFAULT_STORE = "data"
    VAULT_SUFFIX = "vlt"
    META_SUFFIX  = "key"

    # Singleton pattern.
    _instance = None
    
    def __init__(self, statepath = DEFAULT_STORE):
        if VaultManager._instance:
            return # Don't do anything. 
        
        self._dbpath = statepath
        os.makedirs(self._dbpath, exist_ok=True)
        self._vaults = {}
        self._passwds = {}
        self._lock = threading.Lock()

    @classmethod
    def setup(cls, statepath = DEFAULT_STORE):
        if cls._instance is None:
            cls._instance = cls(statepath)

    @classmethod
    def get(cls):
        return cls._instance

    def _vault_fpath(self, vault_id: str) -> str:
        filename = f"{vault_id}.{VaultManager.VAULT_SUFFIX}"
        full_path = os.path.join(self._dbpath, filename)
        return full_path

    def _meta_fpath(self, meta_id: str) -> str:
        filename = f"{meta_id}.{VaultManager.META_SUFFIX}"
        full_path = os.path.join(self._dbpath, filename)
        return full_path

    def _create_metadata(self, metakey: VaultMetaKey) -> bytearray:
        # To store the metadata indexed by the key,
        # create a filename from the key.
        keyid = metakey.as_storage_id()
        filepath = self._meta_fpath(keyid)

        # Check if the file already exists...
        if os.path.isfile(filepath):
            raise RuntimeError("Key file already exists.")

        # Create a new vault name.
        random_name = ""
        # Use alphanumeric characters for the filename
        characters = string.ascii_letters + string.digits
        while True:
            # Generate a random string of the specified length
            random_name = "".join(random.choice(characters) for _ in range(16))
            vaultpath = self._vault_fpath(random_name)
    
            # Check if the file already exists
            if not os.path.exists(vaultpath):
                break


        encrypted_metadata = metakey.generate_encrypted_metadata(random_name)
        if len(encrypted_metadata) == 0:
            raise ValueError("Could not create metadata for writing key file.")

        # Write the metadata to the key file...
        # The 'x' flag will error out if the file already exists.
        with open(filepath, "xb") as metafile:
            metafile.write(encrypted_metadata)

        return encrypted_metadata

    def _get_metadata(self, metakey: VaultMetaKey) -> Tuple[str, SecuredAESCBC, SecuredAESCBC]:
        # To get the metadata indexed by the key,
        # create a filename from the key.
        keyid = metakey.as_storage_id()
        filepath = self._meta_fpath(keyid)

        # Check if the file already exists...
        if os.path.isfile(filepath) is False:
            raise RuntimeError("Key file does not exists.")

        with open(filepath, "rb") as metafile:
            encrypted_metadata = bytearray(metafile.read())

        return metakey.decrypt_metadata(encrypted_metadata)

    def _attach_metadata(self, metakey: VaultMetaKey, vaultid: str, dek: SecuredAESCBC, sek: SecuredAESCBC):
        # To store the metadata indexed by the key,
        # create a filename from the key.
        keyid = metakey.as_storage_id()
        filepath = self._meta_fpath(keyid)

        # Check if the file already exists...
        if os.path.isfile(filepath):
            raise RuntimeError("Key file already exists.")
        encrypted_metadata = metakey.reencrypt_metadata(vaultid, dek, sek)
        if len(encrypted_metadata) == 0:
            raise ValueError("Could not create metadata for writing key file.")

        # Write the metadata to the key file...
        # The 'x' flag will error out if the file already exists.
        with open(filepath, "xb") as metafile:
            metafile.write(encrypted_metadata)

    def exists_key(self, metakey: VaultMetaKey) -> bool:
        keyid = metakey.as_storage_id()
        filepath = self._meta_fpath(keyid)
        return os.path.isfile(filepath)

    def metadata(self, metakey: VaultMetaKey) -> Tuple[str, SecuredAESCBC, SecuredAESCBC]:
        return self._get_metadata(metakey)

    def has_open_vaults(self):
        return len(self._passwds) > 0
        
    def create_vault(self, metakey: VaultMetaKey):
        """Use the meta key to create a vault meta file and the empty vault."""
        vaultid, dek, sek = metakey.decrypt_metadata(self._create_metadata(metakey))
        vault = Vault(sek)
        vault.save(self._vault_fpath(vaultid), dek, overwrite = False)

    def open_vault(self, metakey: VaultMetaKey, passwd: EncryptedSecret) -> str:
        """Returns the vault ID"""
        vaultid, dek, sek = self._get_metadata(metakey)
        with self._lock:
            if vaultid not in self._vaults:
                vault = Vault.load(self._vault_fpath(vaultid), dek, sek)
                self._vaults[vaultid] = {
                    'vault': vault,
                    'dek': dek,
                    'sek': sek
                }

        set_pass = True
        if vaultid in self._passwds:
            # This vault was already open.
            # First check whether the password needs to be changed...
            if self.verify_passwd(vaultid, passwd):
                set_pass = False
        
        if set_pass:
            hashed_str = subprocess_hash_password(passwd.get())
            self._passwds[vaultid] = hashed_str
        return vaultid

    def verify_passwd(self, vaultid: str, passwd: EncryptedSecret):
        if vaultid in self._vaults:
            return subprocess_verify_password(passwd.get(), self._passwds[vaultid])
        return False

    def find_by_passwd(self, passwd: EncryptedSecret):
        for vaultid, curr_passwd in self._passwds.items():
            if self.verify_passwd(vaultid, passwd):
                return vaultid
        return None

    def is_vault_open(self, vaultid: str) -> bool:
        return vaultid in self._vaults

    def _get_open_vault(self, vaultid: str) -> Dict[str,Any]:
        """A simple accessor function to hide the actual map implementation."""
        return self._vaults[vaultid]

    def get_vault(self, vaultid: str) -> Vault:
        """Return the associated vault or throw key error"""
        return self._get_open_vault(vaultid)['vault']

    def attach_vault(self, metakey: VaultMetaKey, vaultid: str):
        """Attach meta key to the associated vault or throw key error"""
        vault_info = self._get_open_vault(vaultid)
        self._attach_metadata(metakey, vaultid, vault_info['dek'], vault_info['sek'])

    def save_vault(self, vaultid: str):
        """Save associated vault or throw key error"""
        dek = self._get_open_vault(vaultid)['dek']
        self.get_vault(vaultid).save(self._vault_fpath(vaultid), dek)

    def create_OTP(self, vaultid: str) -> str:
        raise NotImplementedError("create_OTP is not yet implemented.")

    def validate_OTP(self, otp: str) -> bool:
        raise NotImplementedError("validate_OTP is not yet implemented.")