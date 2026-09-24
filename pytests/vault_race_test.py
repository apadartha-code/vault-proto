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

import os
import random
import string
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

import traceback

from security.framework import SingleUse, SecuredSymmetricKey
from security.obfuscate import KeyObfuscator
from security.aeshelper import AESCBC, SecuredAESCBC
from crypto import mutable_urandom
from vault import Vault

class VaultX(Vault):
    OP_ADD = 1
    OP_DEL = 2
    
    def __init__(self, sek,  keyinfo = {}, records = []):
        super().__init__(sek, keyinfo, records)
        self._q = Queue()
        self._save_active = False
        # self._find_active = False
        # per key tracks...
        self._reads_active = set()
        self._changes_active = set()

    def _serialize(self):
        assert len(self._changes_active) == 0, "Write locks should not be violated by _serialize"
        assert self._save_active is False, "Save lock should not be violated by _serialize"
        
        self._save_active = True
        try:
            result = super()._serialize()
        except:
            result = None
        finally:
            self._save_active = False
        return result

    def _versions(self, key):
        assert len(self._changes_active) == 0, "Write locks should not be violated by _versions"
        
        self._reads_active.add(key)
        result = super()._versions(key)
        self._reads_active.remove(key)
        return result

    def _get(self, key, version):
        assert len(self._changes_active) == 0, "Write locks should not be violated by _get"
        
        self._reads_active.add(key)
        try:
            result = super()._get(key, version)
        except KeyError as ke:
            result = None
        finally:
            self._reads_active.remove(key)
        return result

    def _add(self, vrecord):
        lock_violated = False
        if vrecord.key in self._reads_active or self._save_active is True:
            lock_violated = True
        assert lock_violated is False, "Read lock should not be violated by _add for key: {}.".format(vrecord.key)
        assert vrecord.key not in self._changes_active, "Exclusive write lock should not be violated by _add for key: {}".format(vrecord.key)
        
        self._changes_active.add(vrecord.key)
        self._q.put((VaultX.OP_ADD, vrecord.key, vrecord))
        super()._add(vrecord)
        self._changes_active.remove(vrecord.key)

    def _remove(self, key, version):
        lock_violated = False
        if key in self._reads_active or self._save_active is True:
            lock_violated = True
        assert lock_violated is False, "Read lock should not be violated by _remove for key: {}, version: {}.".format(key, version)
        assert key not in self._changes_active, "Exclusive write lock should not be violated by _remove for key: {}, version: {}.".format(key, version)
        
        self._changes_active.add(key)
        self._q.put((VaultX.OP_DEL, key, version))
        super()._remove(key, version)
        self._changes_active.remove(key)

    def replay_op_queue(self):
        vault = Vault(self._sek)
        while not self._q.empty():
            op, key, data = self._q.get()
            if op == VaultX.OP_ADD:
                try:
                    vault._add(data)
                except:
                    print("DEBUG: replay_op_queue: Add failed for key:", data.key)
            elif op == VaultX.OP_DEL:
                vault._remove(key, data)
            else:
                raise NotImplementedError("Operation {} is not handled for replay.".format(op))
        return vault

    def is_same(self, other_vault):
        if len(self._records) != len(other_vault._records):
            print("DEBUG: is_same: Key counts are different:", len(self._records), len(other_vault._records))
            return False
        for key, versions in self._records.items():
            for v, record in versions.items():
                try:
                    other_record = other_vault._records[key][v]
                    if v == "latest":
                        if record != other_record:
                            print("DEBUG: is_same: latest record is different for key {}:".format(key), record, other_record)
                            return False
                    else:
                        if record.key != other_record.key:
                            print("DEBUG: is_same: records have different keys:", record.key, other_record.key)
                            return False
                        if record.keywords != other_record.keywords:
                            print("DEBUG: is_same: descriptions are different for key {}:".format(key), record.keywords, other_record.keywords)
                            return False
                        if record.encrypted_secret != other_record.encrypted_secret:
                            print("DEBUG: is_same: secrets are different for key {}:".format(key), record.encrypted_secret, other_record.encrypted_secret)
                            return False
                        if record.version != other_record.version:
                            print("DEBUG: is_same: versions are different for key {}:".format(key), record.version, other_record.version)
                            return False
                        # We don't want to compare the timestamps...
                        # if record.ts != other_record.ts: return False
                except:
                    print("DEBUG: is_same: Exception on ({}, {}):".format(key, v), str(e))
                    traceback.print_exc()
                    return False
        return True

class TestClientBase:
    def __init__(self, id, vault, debug = False):
        self.id = id
        self.debug = debug
        self.vault = vault
        self.done = False

    def _run(self):
        raise NotImplementedError("Implement run in derived class.")

    def run(self):
        if self.debug:
            print("Client [{}]: Starting...".format(self.id))

        try:
            self._run()
        except Exception as e:
            print("ERROR:", str(e))
            traceback.print_exc()

        if self.debug:
            print("Client [{}]: ...Done".format(self.id))
        self.done = True


class Saver(TestClientBase):
    FILEPATH = "/tmp/race_test.vlt"
    
    def __init__(self, id, vault, keys, dek, debug = False):
        super().__init__(id, vault, debug)
        self.keys = keys
        self.dek = dek
    
    def _run(self):
        # Wait for at least one key to be created...
        done = False
        passes = 50
        while not done:
            for key in self.keys:
                keyinfo = self.vault.versions(key)
                if keyinfo['next'] > 0:
                    done = True
                    break
            passes -= 1
            if passes == 0:
                break
        # Execute save and be done.
        if self.debug:
            print("Client [{}]: Saving vault.".format(self.id))
        self.vault.save(Saver.FILEPATH, self.dek)
        


class Reader(TestClientBase):
    def __init__(self, id, vault, keys, op_count, debug = False):
        super().__init__(id, vault, debug)
        self.op_keys = random.choices(keys, k = op_count)
    
    def _run(self):
        for key in self.op_keys:
            # Check how many versions (if any) exists
            keyinfo = self.vault.versions(key)
            if len(keyinfo['existing']) > 0:
                v = random.choice(keyinfo['existing'])
                if self.debug:
                    print("Client [{}]: Getting key {}, version {}".format(self.id, key, v))
                record = self.vault.get(key, v)
                if record is None:
                    # It's ok to fail. Maybe there's a race condition.
                    if self.debug:
                        print("Client [{}]: Getting key {}, version {} failed.".format(self.id, key, v))


class Writer(TestClientBase):
    def __init__(self, id, vault, keys, op_count, debug = False):
        super().__init__(id, vault, debug)
        self.op_keys = random.choices(keys, k = op_count)
    
    def _run(self):
        for key in self.op_keys:
            # Check how many versions (if any) exists
            keyinfo = self.vault.versions(key)
            if keyinfo['next'] == 0:
                # Add.
                if self.debug:
                    print("Client [{}]: Adding key {}".format(self.id, key))
                try:
                    self.vault.add(key, SingleUse(mutable_urandom(8)), desc = key)
                except ValueError as e:
                    # It's ok to fail. Maybe there's a race condition.
                    if self.debug:
                        print("Client [{}]: Adding key {} failed:".format(self.id, key), str(e))
                except Exception as e:
                    traceback.print_exc()
            else:
                versions = keyinfo['existing']
                if len(versions) == 0 or random.random() < (1.0 / len(versions)):
                    # Perform an update
                    if self.debug:
                        print("Client [{}]: Updating key {}".format(self.id, key))
                    self.vault.update(key, SingleUse(mutable_urandom(8)), desc = key)
                else:
                    # Perform a delete.
                    ver = random.choice(versions)
                    if self.debug:
                        print("Client [{}]: Deleting key {}, version: {}".format(self.id, key, ver))
                    try:
                        self.vault.del_version(key, ver)
                    except KeyError as ke:
                        if self.debug:
                            print("Client [{}]: Deleting key {} (version: {}) failed:".format(self.id, key, ver), str(ke))
                    except Exception as e:
                        traceback.print_exc()

def random_key_str(n):
    random_str = ""
    # Use alphanumeric characters for the filename
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k = n))

def test_vault_race(nclients, nops):
    if nclients < 2:
        raise ValueError("Need at least 2 clients.")
    all_keys = []
    client_keys = []
    client_ids = list(range(nclients))
    for _ in client_ids:
        random_key = random_key_str(6)
        client_keys.append([ random_key ])
        all_keys.append(random_key)
    min_share = min(nclients, 2)
    for _ in range(nclients // 2):
        shared_key = random_key_str(6)
        all_keys.append(shared_key)
        cids = random.sample(client_ids, k = min_share)
        for cid in cids:
            client_keys[cid].append(shared_key)

    master_key = SecuredAESCBC.random(KeyObfuscator(SecuredAESCBC.KEYBYTES))

    sek = SecuredAESCBC.random(master_key)
    dek = SecuredAESCBC.random(master_key)
    vault = VaultX(sek)
    clients = [ Writer(cid, vault, client_keys[cid], nops, debug = True) for cid in client_ids ]
    clients.append(Reader(nclients, vault, all_keys, nclients * nops, debug = True))
    clients.append(Reader(nclients + 1, vault, all_keys, nclients * nops, debug = True))
    clients.append(Saver(nclients + 2, vault, all_keys, dek, debug = True))
    clients.append(Saver(nclients + 3, vault, all_keys, dek, debug = True))

    # Run the clients in parallel threads
    with ThreadPoolExecutor() as executor:
        # Use a lambda to call the method on each instance passed by map
        results = executor.map(lambda obj: obj.run(), clients)

    reload_error = False
    try:
        reloaded_vault = Vault.load(Saver.FILEPATH, dek, sek)
    except Exception as e:
        reload_error = True
    assert reload_error is False, "Saved vault should reload without error."

    print("DEBUG: Starting replay...")
    replayed_vault = vault.replay_op_queue()
    assert vault.is_same(replayed_vault), "Final outcome should match single threaded replay of queue of operations."
    print("\nPASSED: Data is coherent after race and consistent with reload and single threaded replay.")

if __name__ == "__main__":
    test_vault_race(3, 10)