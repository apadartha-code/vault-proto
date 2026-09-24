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

###
# python -m pytests.vault_test
#

import os
import random
import itertools
from pathlib import Path

import traceback

from security.framework import SingleUse, SecuredSymmetricKey
from security.obfuscate import KeyObfuscator
from security.aeshelper import AESCBC, SecuredAESCBC
from crypto import mutable_urandom
from vault import VaultRecord, Vault

g_test_vault_state = {
    'master_key': SecuredAESCBC.random(KeyObfuscator(SecuredAESCBC.KEYBYTES)),
    'keyspecs0': [
        ('key0', 5, None),
        ('key1.long.default', 512, None),
        ('key1.long.with_desc', 876, "This key has a description."),
        ('key2.short.with_desc', 12, "This key also has a description.")
    ]
}


def all_combos(*tuple_pairs):
    """
    good, bad = all_combos((good_list1, bad_list1), (good_list2, bad_list2), ...)
    
    Safely generates good and bad combinations even for unhashable types 
    like dicts and lists.
    """
    good_combos = []
    bad_combos = []
    
    # Tag each list with a boolean: True for Good, False for Bad
    # This transforms (good_list, bad_list) into ((True, good_list), (False, bad_list))
    tagged_pairs = [((True, good), (False, bad)) for good, bad in tuple_pairs]
    
    # Iterate through all 2^k possible combinations of Good/Bad lists
    for list_selection in itertools.product(*tagged_pairs):
        
        # list_selection is a k-tuple of (is_good, list_of_values)
        # We check if this specific selection consists entirely of 'Good' lists
        is_all_good = all(is_good for is_good, _ in list_selection)
        
        # Extract just the raw lists for this iteration
        lists_to_combine = [lst for _, lst in list_selection]
        
        # Generate the combinations for this specific block
        block_combos = itertools.product(*lists_to_combine)
        
        # Route the entire block of combos to the right bucket without checking elements
        if is_all_good:
            good_combos.extend(block_combos)
        else:
            bad_combos.extend(block_combos)
            
    return good_combos, bad_combos

def kwargs_copy(kwargs):
    copied = {}
    for k, v in kwargs.items():
        copied[k] = v
    return copied

def prepare_kwargs_for_add_or_update(kwargs):
    kwargs2 = kwargs_copy(kwargs)
    secret = kwargs2.get('secret')
    if isinstance(secret, bytearray) is False:
        if isinstance(secret, bytes):
            secret = bytearray(secret)
        else:
            # print("Can't convert to bytearray:", secret, type(secret))
            raise ValueError("Invalid type {} for conversion to bytearray".format(type(secret)))
    kwargs2['wrapped_secret'] = SingleUse(secret.copy())
    del kwargs2['secret']
    return kwargs2

"""
# --- Example Usage with Unhashable Types ---

# Tuples containing unhashable lists and dicts
list1 = ( [{'id': 1}], [{'id': 9}] )
list2 = ( [[10, 20]], [[99, 99]] )

good, bad = get_combo_splits_safe(list1, list2)

print("Good Combos:")
for c in good:
    print(c)

print("\nBad Combos:")
for c in bad:
    print(c)
"""


class DefaultValue:
    def __init__(self, val):
        self.val = val


class ComboGenerator:
    def __init__(self):
        self.good_bad_tuple_pairs = []
        self.arg_idx = []

    def add_arg(self, arg_name, good_vals, bad_vals):
        if arg_name in self.arg_idx:
            raise ValueError("Values for argument {} has already been added".format(arg_name))
        self.arg_idx.append(arg_name)
        goodlist = [ (('g', i), v) for i, v in enumerate(good_vals) ]
        badlist = [ (('b', i), v) for i, v in enumerate(bad_vals) ]
        self.good_bad_tuple_pairs.append((goodlist, badlist))

    def generate_indexed_combos(self):
        return all_combos(*self.good_bad_tuple_pairs)

    def make_arg_map(self, combo):
        arg_map = {}
        for i in range(len(combo)):
            idx, val = combo[i]
            arg_map[self.arg_idx[i]] = { 'v': val, 'i': idx, 'd': isinstance(val, DefaultValue) }
        return arg_map

    def make_kwargs(self, combo):
        arg_map = {}
        idx_map = {}
        for i in range(len(combo)):
            idx, val = combo[i]
            if isinstance(val, DefaultValue) is False:
                arg_map[self.arg_idx[i]] = val
            idx_map[self.arg_idx[i]] = idx
        return arg_map, idx_map


def test_vault_create_bad_args():
    cg = ComboGenerator()
    good_sek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    cg.add_arg('sek', [ good_sek ], [ None, bytearray(32) ])
    nontrivial_keyinfo = { 'new key': { Vault.NEXT_VERSION: 0 } }
    cg.add_arg('keyinfo', [ {}, nontrivial_keyinfo ], [ None, [], { 1, 2, -50 }, [-20, 0, 50], [ ('a', 0), ('z', 25) ] ])
    nontrivial_records = [ VaultRecord.new_record("123456", mutable_urandom(32)) ]
    cg.add_arg('records', [ [], nontrivial_records ], [ None, {}, { 1, 2, -50 }, [-20, 0, 50], [ ('a', 0), ('z', 25) ] ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 4, "There should be four good combos."

    for bc in bad_combos:
        error = False
        arg_map = cg.make_arg_map(bc)
        try:
            vault = Vault(arg_map['sek']['v'], arg_map['keyinfo']['i'], arg_map['records']['v'])
        except:
            error = True
        assert error, "Vault constructor should throw error on (sek: {}, keyinfo: {}, records: {})".format(arg_map['sek']['i'], arg_map['keyinfo']['i'], arg_map['records']['i'])

    error = False
    try:
        vault = Vault(good_sek, nontrivial_keyinfo, nontrivial_records)
    except:
        error = True
    assert error, "Vault constructor should throw error on mismatch of keyinfo and keys in records."

def test_vault_save_no_overwrite_bad_args(vault):
    existing_filepath = "/tmp/existing_file.vlt"
    existing_path = Path(existing_filepath)
    existing_path.touch()
    existing_ts = existing_path.stat().st_mtime
    
    existing_dirpath = "/tmp/existing_dir.vlt"
    Path(existing_dirpath).mkdir(exist_ok=True)
    
    new_filepath = "/tmp/newvault.vlt" # Do not pre-create this.
    
    cg = ComboGenerator()
    cg.add_arg('filepath', [ new_filepath ], [ existing_dirpath, existing_filepath ])
    cg.add_arg('dek', [ SecuredAESCBC.random(g_test_vault_state['master_key']) ], [ None, bytearray(32) ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 1, "There should be one good combo."

    for bc in bad_combos:
        error = False
        arg_map = cg.make_arg_map(bc)
        try:
            vault.save(arg_map['filepath']['v'], arg_map['dek']['v'], overwrite = False)
            # Some cases fail sliently...
            if arg_map['filepath']['v'] == existing_filepath:
                if existing_ts == existing_path.stat().st_mtime:
                    error = True
        except:
            error = True
        assert error, "Vault save should throw error on (filepath: {}, dek: {})".format(arg_map['filepath']['i'], arg_map['dek']['i'])

def test_vault_save_w_overwrite_bad_args(vault, existing_filepath):
    existing_path = Path(existing_filepath)
    existing_path.touch()
    existing_ts = existing_path.stat().st_mtime
    
    existing_dirpath = "/tmp/existing_dir.vlt"
    Path(existing_dirpath).mkdir(exist_ok=True)
    
    new_filepath = "/tmp/newvault.vlt" # Do not pre-create this.
    
    cg = ComboGenerator()
    cg.add_arg('filepath', [ new_filepath, existing_filepath ], [ existing_dirpath ])
    cg.add_arg('dek', [ SecuredAESCBC.random(g_test_vault_state['master_key']) ], [ None, bytearray(32) ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 2, "There should be two good combos."

    for bc in bad_combos:
        error = False
        arg_map = cg.make_arg_map(bc)
        try:
            vault.save(arg_map['filepath']['v'], arg_map['dek']['v'])
            # Some cases fail sliently...
            if arg_map['filepath']['v'] == existing_filepath:
                if existing_ts == existing_path.stat().st_mtime:
                    error = True
        except:
            error = True
        assert error, "Vault save should throw error on (filepath: {}, dek: {})".format(arg_map['filepath']['i'], arg_map['dek']['i'])

def test_vault_load_bad_args(filepath, dek, sek):
    bad_filepath = "/tmp/bad_file.vlt"
    nonexistent_filepath = "/tmp/nosuchfile.vlt"
    existing_dirpath = "/tmp/existing_dir.vlt"

    with open(bad_filepath, "wb") as dummyfile:
        dummyfile.write(os.urandom(1024))
    
    cg = ComboGenerator()
    cg.add_arg('filepath', [ filepath ], [ bad_filepath, existing_dirpath, nonexistent_filepath ])
    cg.add_arg('dek', [ dek ], [ SecuredAESCBC.random(g_test_vault_state['master_key']), None, bytearray(32) ])
    cg.add_arg('sek', [ sek ], [ SecuredAESCBC.random(g_test_vault_state['master_key']), None, bytearray(32) ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 1, "There should be one good combo."

    for bc in bad_combos:
        error = False
        vault = None
        arg_map = cg.make_arg_map(bc)
        try:
            vault = Vault.load(arg_map['filepath']['v'], arg_map['dek']['v'], arg_map['sek']['v'])
        except:
            error = True
        assert error, "Vault load should throw error on (filepath: {}, dek: {}, sek: {})".format(arg_map['filepath']['i'], arg_map['dek']['i'], arg_map['sek']['i'])

def test_vault_add_bad_args(vault):
    cg = ComboGenerator()
    cg.add_arg('key', [ "good key" ], [ "", None, 42, bytearray(4) ])
    cg.add_arg('secret', [ bytearray(os.urandom(8)) ], [ None, bytearray(), "", "abracadabra" ])
    cg.add_arg('desc', [ DefaultValue(""), "Valid description." ], [ None, bytearray(80), 302 ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 2, "There should be two good combos."

    for bc in bad_combos:
        error = False
        kwargs, arg_idx = cg.make_kwargs(bc)
        try:
            kwargs2 = prepare_kwargs_for_add_or_update(kwargs)
            vault.add(**kwargs2)
        except:
            error = True
        assert error, "Vault add should throw error on (key: {}, secret: {}, desc: {})".format(arg_idx['key'], arg_idx['secret'], arg_idx['desc'])

def test_vault_update_bad_args(vault, existing_keys):
    good_keys = [ "new key as update" ]
    good_keys.extend(existing_keys)
    cg = ComboGenerator()
    cg.add_arg('key', good_keys, [ "", None, 42, bytearray(4) ])
    cg.add_arg('secret', [ bytearray(os.urandom(8)) ], [ None, bytearray(), "", "abracadabra" ])
    cg.add_arg('desc', [ DefaultValue(""), "Valid description." ], [ None, bytearray(80), 302 ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == len(good_keys) * 2, "Count of good combos should match expected."

    for bc in bad_combos:
        error = False
        kwargs, arg_idx = cg.make_kwargs(bc)
        try:
            kwargs2 = prepare_kwargs_for_add_or_update(kwargs)
            vault.add(**kwargs2)
        except:
            error = True
        assert error, "Vault update should throw error on (key: {}, secret: {}, desc: {})".format(arg_idx['key'], arg_idx['secret'], arg_idx['desc'])

def test_vault_get_bad_args(vault, existing_key, existing_version, nonexistent_keys, invalid_version):
    cg = ComboGenerator()
    bad_keys = [ "", None, 42, bytearray(4), existing_key.encode('utf-8') ]
    bad_keys.extend(nonexistent_keys)
    cg.add_arg('key', [ existing_key ], bad_keys)
    cg.add_arg('version', [ DefaultValue(-1), existing_version, -1 ], [ None, "foo", 3.14159, b'0', bytearray(4), invalid_version ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 3, "There should be three good combos."

    for bc in bad_combos:
        error = False
        kwargs, arg_idx = cg.make_kwargs(bc)
        try:
            vault.get(**kwargs)
        except:
            error = True
        assert error, "Vault get should throw error on (key: {}, version: {})".format(arg_idx['key'], arg_idx['version'])

def test_vault_secret_bad_args(vault, existing_key, existing_version, nonexistent_keys, invalid_version):
    cg = ComboGenerator()
    bad_keys = [ "", None, 42, bytearray(4), existing_key.encode('utf-8') ]
    bad_keys.extend(nonexistent_keys)
    cg.add_arg('key', [ existing_key ], bad_keys)
    cg.add_arg('version', [ DefaultValue(-1), existing_version, -1 ], [ None, "foo", 3.14159, b'0', bytearray(4), invalid_version ])
    good_combos, bad_combos = cg.generate_indexed_combos()
    assert len(good_combos) == 3, "There should be three good combos."

    for bc in bad_combos:
        error = False
        arg_map = cg.make_arg_map(bc)
        kwargs, arg_idx = cg.make_kwargs(bc)
        try:
            secret = vault.secret(**kwargs)
            if secret is None:
                error = True
        except:
            error = True
        assert error, "Vault secret should throw error on (key: {}, version: {})".format(arg_idx['key'], arg_idx['version'])

def test_vault_versions_bad_args(vault, existing_key, nonexistent_keys):
    bad_keys = [ "", None, 42, bytearray(4), existing_key.encode('utf-8') ]
    # bad_keys.extend(nonexistent_keys)

    for k in bad_keys:
        error = False
        try:
            result = vault.versions(k)
        except:
            error = True
        assert error, "Vault versions should throw error on key: {}".format(k)

    for k in nonexistent_keys:
        error = False
        try:
            result = vault.versions(k)
        except Exception as e:
            print("ERROR:", str(e))
            traceback.print_exc()
            error = True
        assert error is False, "Vault versions should not throw error on nonexistent key: {}".format(k)
        assert 'existing' in result, "Vault versions result for nonexistent key {} should have key for existing versions.".format(k)
        assert 'next' in result, "Vault versions result for nonexistent key {} should have key for next version.".format(k)
        assert isinstance(result['existing'], list), "Vault versions result for nonexistent key {} should have list for existing versions.".format(k)
        assert isinstance(result['next'], int), "Vault versions result for nonexistent key {} should have int for next version.".format(k)
        assert len(result['existing']) == 0, "Vault versions result for nonexistent key {} should have empty list for existing versions.".format(k)
        assert result['next'] == 0, "Vault versions result for nonexistent key {} should have value 0 for next version.".format(k)

def test_vault_del_version_bad_args(vault, existing_key, existing_vers):
    invalid_vers = [ 'latest', 1.234, b'\x00', None ]
    for v in invalid_vers:
        error = False
        try:
            vault.del_version(existing_key, v)
        except:
            error = True
        assert error, "Vault del_version should throw error on version: {}".format(v)
        
def test_vault_find_bad_args(vault):
    for q in [ 1234, None, b'something', False ]:
        error = False
        try:
            vault.find(q)
        except:
            error = True
        assert error, "Vault find should throw error on query: {}".format(q)


def test_vault_create_empty(sek):
    error = False
    vault = None
    try:
        vault = Vault(sek)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault constructor should not throw error."
    return vault

def test_vault_save_no_overwrite(vault, filepath, dek):
    error = False
    Path(filepath).unlink(missing_ok = True)
    try:
        vault.save(filepath, dek, overwrite = False)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault save should not throw error."

def test_vault_save_w_overwrite(vault, filepath, dek):
    error = False
    try:
        vault.save(filepath, dek)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault save with overwrite should not throw error."

def test_vault_save_skip_unchanged(vault, existing_filepath, dek):
    existing_path = Path(existing_filepath)
    existing_path.touch()
    existing_ts = existing_path.stat().st_mtime
    
    error = False
    try:
        vault.save(existing_filepath, dek)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault save unchanged should not throw error."
    assert existing_ts == existing_path.stat().st_mtime, "Vault save unchanged should not update the saved state on disk."

def test_vault_load(filepath, dek, sek):
    error = False
    vault = None
    try:
        vault = Vault.load(filepath, dek, sek)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault load should not throw error."
    return vault

def test_helper_kwargs_for_add_or_update(key, secret, desc, default_desc = False, add_missing = None):
    kwargs = { 'key': key, 'secret': secret.copy() }
    if desc is not None:
        kwargs['desc'] = desc
    if default_desc is not None:
        kwargs['default_desc'] = default_desc
    if add_missing is not None:
        # Applies to updates only!
        kwargs['add_missing'] = add_missing
    return kwargs

def test_vault_add(vault, kwargs):
    error = False
    kwargs2 = prepare_kwargs_for_add_or_update(kwargs)
    try:
        vault.add(**kwargs2)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault add should not throw error."

def test_vault_duplicate_add(vault, kwargs):
    error = False
    try:
        kwargs2 = prepare_kwargs_for_add_or_update(kwargs)
        vault.add(**kwargs2)
    except Exception as e:
        error = True
    assert error, "Vault duplicate add should throw error for key {}.".format(kwargs['key'])

def test_vault_update(vault, kwargs, will_fail = False):
    error = False
    kwargs2 = prepare_kwargs_for_add_or_update(kwargs)
    try:
        vault.update(**kwargs2)
    except Exception as e:
        if not will_fail:
            # Not an expected error.
            print("ERROR:", str(e))
            traceback.print_exc()
        error = True
    if not will_fail:
        assert error is False, "Vault update should not throw error."
    else:
        assert error, "Vault update should throw error."

def test_vault_key_retrieval_default(vault, key, key_info):
    error = False
    try:
        record = vault.get(key)
        wrapped_secret = vault.secret(key)
    except Exception as e:
        error = True
    assert error is False, "Vault get or secret (default version) should not throw error for key {}.".format(key)
    assert key == record.key, "Record key should match retrieval key {}".format(key)

    default_version = key_info.default_version()
    default_secret, dflt_desc, _ = key_info.versions[default_version]
    with wrapped_secret.revealed() as secret:
        assert secret == default_secret, "Retrieved secret should match expected value for key {}".format(key)
        assert secret != record.encrypted_secret, "Secret should be encrypted in vault record. Key: {}".format(key)
    assert record.version == default_version, "Record version {} should be the default {} for key {}".format(record.version, default_version, key)
    dflt_desc = key_info.expected_desc[default_version]
    if dflt_desc is None:
        dflt_desc = key
    assert record.keywords == dflt_desc, "Record description \'{}\' should match expected value \'{}\' for key {}, version {}.".format(record.keywords, dflt_desc, key, default_version)

def test_vault_key_retrieval_by_ver(vault, key, key_info, version):
    error = False
    try:
        record = vault.get(key, version)
        wrapped_secret = vault.secret(key, version)
    except Exception as e:
        error = True
    assert error is False, "Vault get or secret should not throw error for key {}.".format(key)
    assert key == record.key, "Record key should match retrieval key {}".format(key)
    assert record.version == version, "Record version {} should match query version {} for key {}".format(record.version, version, key)

    ver_secret, ver_desc, _ = key_info.versions[version]
    with wrapped_secret.revealed() as secret:
        assert secret == ver_secret, "Retrieved secret {} should match expected value {} for key \'{}\', version {}".format(secret, ver_secret, key, version)
        assert secret != record.encrypted_secret, "Secret should be encrypted in vault record. Key: {}".format(key)
    ver_desc = key_info.expected_desc[version]
    if ver_desc is None:
        ver_desc = key
    assert record.keywords == ver_desc, "Record description \'{}\' should match expected value \'{}\' for key {}, version {}.".format(record.keywords, ver_desc, key, version)

def test_vault_del_key(vault, key):
    error = False
    try:
        vault.del_key(key)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault del_key should not throw error."
    # Ensure that the key is no longer found.
    try:
        record = vault.get(key)
    except Exception as e:
        error = True
    assert error is True, "Vault get should throw error on key after deletion."

def test_vault_del_version(vault, key, ver):
    error = False
    default_version = -1
    try:
        if ver is None:
            record = vault.get(key)
            default_version = record.version
            vault.del_version(key, default_version)
        else:
            record = vault.get(key, ver)
            vault.del_version(key, ver)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault del_version should not throw error."
    # Ensure that the key - version is no longer found.
    try:
        if ver is None:
            record = vault.get(key)
            if record.version != default_version:
                error = True
        else:
            record = vault.get(key, ver)
    except Exception as e:
        error = True
    assert error is True, "Vault get should throw error on key + version after deletion."

def test_vault_find(vault, query, expected_keys_n_vers):
    error = False
    expected_count = len(expected_keys_n_vers)
    actual_keys_n_vers = []
    try:
        if expected_count > 5:
            actual_keys_n_vers = vault.find(query, max_count = expected_count)
        else:
            actual_keys_n_vers = vault.find(query)
    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        error = True
    assert error is False, "Vault find should not throw error."

    assert len(actual_keys_n_vers) == expected_count, "Find should return {} results for query: {}".format(expected_count, query)
    dedups = set(actual_keys_n_vers)
    assert dedups == set(expected_keys_n_vers), "The set of result indices should match expected for query: {}".format(query)


class TestRecordVersions:
    def __init__(self):
        self.versions = {}
        self.expected_desc = {}
        self.next_version = 0

    def set_expected_desc(self, v, desc, default_desc):
        if desc:
            # description is not None - which will implicitly become ""
            # through default in add or update ...
            # and it is not explicitly "" ...
            self.expected_desc[v] = desc
        elif default_desc is False:
            # Override is disabled.
            self.expected_desc[v] = ""
        else:
            # Override enabled and empty description.
            # Look for previous desc.
            latest_v = self.default_version()
            if latest_v is not None:
                latest_desc = self.expected_desc[latest_v]
                # Copy from previous only if it is not empty.
                if latest_desc is None or len(latest_desc) > 0:
                    self.expected_desc[v] = latest_desc
                else:
                    self.expected_desc[v] = None
            else:
                # There is no previous version and the desc should
                # default to the key, which we don't have in this case.
                self.expected_desc[v] = None

    def add(self, secret, desc, default_desc = False):
        v = self.next_version
        self.next_version += 1
        self.set_expected_desc(v, desc, default_desc)
        self.versions[v] = (secret, desc, default_desc)

    def pop(self):
        if self.next_version > 0:
            self.next_version -= 1
        else:
            raise RuntimeError("Cannot pop empty collection.")
        if self.next_version in self.versions:
            del self.versions[self.next_version]

    def delete(self, version):
        del self.versions[version]
        del self.expected_desc[version]

    def default_version(self):
        if len(self.versions) > 0:
            return max(self.versions.keys())
        return None

def test_helper_check_all_existing_keys_n_vers(vault, test_data):
    # Check for the existing keys and versions.
    for k, arg_map in test_data.items():
        test_vault_key_retrieval_default(vault, k, arg_map)

        verinfo = vault.versions(k)
        assert len(verinfo['existing']) == len(arg_map.versions), "Count of existing versions for key {} should be {}".format(k, len(arg_map.versions))
        for v in arg_map.versions:
            assert v in verinfo['existing'], "Version {} should be an existing version.".format(v)
            test_vault_key_retrieval_by_ver(vault, k, arg_map, v)
    
'''
Vault tests:
'''
'''
- Journey 1:
  - Create a new vault
  - Save it
  - Load it again
'''
def test_journey1():
    # Test create with bad args.
    test_vault_create_bad_args()

    # Test create (empty) with proper (default) args.
    sek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    vault = test_vault_create_empty(sek)

    # Test first save with bad args.
    test_vault_save_no_overwrite_bad_args(vault)

    # Test first save with proper args.
    filepath = "/tmp/journey1.vlt"
    dek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    test_vault_save_no_overwrite(vault, filepath, dek)
    
    # Test load with bad args.
    test_vault_load_bad_args(filepath, dek, sek)

    # Test load with proper args.
    vault = test_vault_load(filepath, dek, sek)

    # Test save is skipped for unchanged vault.
    test_vault_save_skip_unchanged(vault, filepath, dek)
    print("Journey 1: Empty vault create, save & load works.")

'''
- Journey 2:
  - Load an empty vault
  - Add some keys
  - Retrieve the keys
  - Save the vault
  - Load the vault again
  - Check that the keys are there.
'''
def test_journey2():
    filepath = "/tmp/journey2.vlt"
    Path(filepath).unlink(missing_ok = True) # Remove leftover path from previous test fails.
    
    dek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    sek = SecuredAESCBC.random(g_test_vault_state['master_key'])

    # Create, save and load the empty vault.
    new_v = Vault(sek)
    new_v.save(filepath, dek)
    vault = Vault.load(filepath, dek, sek)
    # Save the empty vault so we can test overwrite.
    test_vault_save_no_overwrite(vault, filepath, dek)

    # Test add with bad args.
    test_vault_add_bad_args(vault)

    # Test add with actual args.
    keyspecs = g_test_vault_state['keyspecs0']
    test_data = {}
    for key, secret_len, desc in keyspecs:
        test_data[key] = TestRecordVersions()
        secret = bytearray(os.urandom(secret_len))
        test_data[key].add(secret, desc)
        add_kwargs = test_helper_kwargs_for_add_or_update(key, secret, desc)
        test_vault_add(vault, add_kwargs)

    # Test duplicate add.
    for k, attribs in test_data.items():
        secret, desc, _ = attribs.versions[0]
        add_kwargs = test_helper_kwargs_for_add_or_update(k, secret, desc)
        test_vault_duplicate_add(vault, add_kwargs)

    # Test get and secret with bad args. And, versions too.
    nonexistent_keys = [ 'key0.nonexistent', 'bad key' ]
    test_vault_get_bad_args(vault, keyspecs[0][0], 0, nonexistent_keys, 1)
    test_vault_secret_bad_args(vault, keyspecs[0][0], 0, nonexistent_keys, 1)
    test_vault_versions_bad_args(vault, keyspecs[0][0], nonexistent_keys)
    
    # Check for the keys.
    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    # Test saving the vault with bad args.
    test_vault_save_w_overwrite_bad_args(vault, filepath)

    # Test actual save of non-empty vault.
    test_vault_save_w_overwrite(vault, filepath, dek)
    
    # Test load with bad args for non-empty vault.
    test_vault_load_bad_args(filepath, dek, sek)

    # Test load with proper args.
    reloaded_vault = test_vault_load(filepath, dek, sek)

    # Test add with bad args.
    test_vault_add_bad_args(reloaded_vault)

    # Test add after reload with actual args.
    keyspecs2 = [
        ('new_key', 5, None),
        ('new_key.with_desc', 12, "This key also has a description.")
    ]
    for key, secret_len, desc in keyspecs2:
        test_data[key] = TestRecordVersions()
        secret = bytearray(os.urandom(secret_len))
        test_data[key].add(secret, desc)
        add_kwargs = test_helper_kwargs_for_add_or_update(key, secret, desc)
        test_vault_add(reloaded_vault, add_kwargs)

    # Test duplicate add.
    for k, attribs in test_data.items():
        secret, desc, _ = attribs.versions[0]
        add_kwargs = test_helper_kwargs_for_add_or_update(k, secret, desc)
        test_vault_duplicate_add(reloaded_vault, add_kwargs)

    # Test get and secret with bad args.
    nonexistent_keys = [ 'key0.nonexistent', 'bad key' ]
    test_vault_get_bad_args(reloaded_vault,  keyspecs[0][0], 0, nonexistent_keys, 1)
    test_vault_secret_bad_args(reloaded_vault,  keyspecs[0][0], 0, nonexistent_keys, 1)
    
    # Check for the keys.
    test_helper_check_all_existing_keys_n_vers(reloaded_vault, test_data)
    print("Journey 2: Add key, retrieve key, duplicate keys, save, load, retest keys, retest duplicate adds... works.")

'''
- Journey 3:
  - Load an existing vault
  - Delete a key
  - Check that the key cannot be retrieved
  - Update some keys
    - Get the latest version (as default)
    - Get an older version
  - Add new keys through update
  - Retrieve the keys
  - Save the vault
  - Load the vault again
  - Check that the keys are there.
'''
def test_journey3():
    filepath = "/tmp/journey3.vlt"
    Path(filepath).unlink(missing_ok = True) # Remove leftover path from previous test fails.
    
    dek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    sek = SecuredAESCBC.random(g_test_vault_state['master_key'])

    # Create, save and load the empty vault.
    new_v = Vault(sek)
    new_v.save(filepath, dek)
    vault = Vault.load(filepath, dek, sek)

    # Test add with actual args.
    keyspecs = g_test_vault_state['keyspecs0']
    test_data = {}
    for key, secret_len, desc in keyspecs:
        test_data[key] = TestRecordVersions()
        secret = bytearray(os.urandom(secret_len))
        test_data[key].add(secret, desc)
        add_kwargs = test_helper_kwargs_for_add_or_update(key, secret, desc)
        test_vault_add(vault, add_kwargs)

    deleted_key = keyspecs[0][0] # Remove the first key.
    # Test del_key.
    test_vault_del_key(vault, deleted_key)

    # Check retrieval for bad args, including deleted key...
    nonexistent_keys = [ 'key0.nonexistent', 'bad key', deleted_key ]
    test_vault_get_bad_args(vault,  keyspecs[1][0], 0, nonexistent_keys, 1)
    test_vault_secret_bad_args(vault,  keyspecs[1][0], 0, nonexistent_keys, 1)
    test_vault_versions_bad_args(vault, keyspecs[1][0], nonexistent_keys)
    
    del test_data[deleted_key]
    # Check for the remaining keys.
    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    # Test actual save of non-empty vault.
    test_vault_save_w_overwrite(vault, filepath, dek)

    # Test load with proper args.
    vault = test_vault_load(filepath, dek, sek)

    # Check retrieval for bad args, including deleted key...
    nonexistent_keys = [ 'key0.nonexistent', 'bad key', deleted_key ]
    test_vault_get_bad_args(vault, keyspecs[1][0], 0, nonexistent_keys, 1)
    test_vault_secret_bad_args(vault, keyspecs[1][0], 0, nonexistent_keys, 1)
    test_vault_versions_bad_args(vault, keyspecs[1][0], nonexistent_keys)
    
    # Check for the remaining keys.
    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    # Test update with bad args.
    test_vault_update_bad_args(vault, list(test_data.keys()))

    deleted_key2 = keyspecs[-1][0] # Remove the last key.
    # Test del_key after reload.
    test_vault_del_key(vault, deleted_key2)
    del test_data[deleted_key2]

    # Test update after reload with actual args. Do not update desc.
    for key, secret_len, desc in keyspecs:
        if key not in test_data:
            test_data[key] = TestRecordVersions()
            desc = None
        secret = bytearray(os.urandom(secret_len))
        test_data[key].add(secret, desc)
        update_kwargs = test_helper_kwargs_for_add_or_update(key, secret, desc)
        test_vault_update(vault, update_kwargs)
    
    # Check for the existing keys.
    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    # Test save of updated vault.
    test_vault_save_w_overwrite(vault, filepath, dek)

    # Test load with proper args.
    reloaded_vault = test_vault_load(filepath, dek, sek)

    # Check retrieval for bad args ...
    nonexistent_keys = [ 'key0.nonexistent', 'bad key' ]
    test_vault_get_bad_args(reloaded_vault, keyspecs[1][0], 0, nonexistent_keys, 2)
    test_vault_secret_bad_args(reloaded_vault, keyspecs[1][0], 0, nonexistent_keys, 2)
    
    # Check for the existing keys.
    test_helper_check_all_existing_keys_n_vers(reloaded_vault, test_data)
    print("Journey 3: Add key, delete key, save, load, check keys, update keys. save, load, retest keys... works.")

'''
- Journey 4:
  - Load an existing vault which has a key with three versions, each with a different description for search.
    - If not, add the keys as required.
  - Delete the oldest version of the key. Check vault for consistency.
      - Ensure that the other two versions can be retrieved.
      - Ensure that the latest version is correctly retrieved.
      - Ensure that the oldest version cannot be retrieved.
      - Ensure that search with common keywords find the remaining versions.
      - Ensure that search with the specific keyword for the deleted version(s) does not find it/them.
  - Save the vault
  - Load the vault again. Check vault for consistency.
  - Delete the latest version. Check vault for consistency across reload.
      - Ensure that the remaining version can be retrieved.
      - Ensure that the latest version is correctly retrieved.
      - Ensure that the deleted versions cannot be retrieved.
      - Ensure that search with common keywords find the remaining versions.
      - Ensure that search with the specific keyword for the deleted version(s) does not find it/them.
  - Update the version of the key. Check vault for consistency across reload.
      - Ensure that the two expected versions can be retrieved.
      - Ensure that the latest version is correctly retrieved.
      - Ensure that the deleted versions cannot be retrieved.
      - Ensure that search with common keywords find the remaining versions.
      - Ensure that search with the specific keyword for the deleted version(s) does not find it/them.
  - Delete all versions of the key. Check for consistency across reload.
      - Ensure that no version of the key can be retrieved.
      - Ensure that search with the specific keyword for the deleted version(s) does not find it/them.
      - Ensure that all other key and versions are unchanged.
'''
def test_helper_reload(vault, path, dek, sek):
    # Test save of updated vault.
    test_vault_save_w_overwrite(vault, path, dek)

    # Test load with proper args.
    return test_vault_load(path, dek, sek)

def test_journey4():
    filepath = "/tmp/journey4.vlt"
    Path(filepath).unlink(missing_ok = True) # Remove leftover path from previous test fails.
    
    dek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    sek = SecuredAESCBC.random(g_test_vault_state['master_key'])

    # Start with an empty vault.
    vault = Vault(sek)

    # Test add with actual args.
    keyspecs = g_test_vault_state['keyspecs0']
    test_data = {}
    for key, secret_len, desc in keyspecs:
        test_data[key] = TestRecordVersions()
        secret = bytearray(os.urandom(secret_len))
        test_data[key].add(secret, desc)
        add_kwargs = test_helper_kwargs_for_add_or_update(key, secret, desc)
        test_vault_add(vault, add_kwargs)

    # Test find with bad args.
    test_vault_find_bad_args(vault)

    # Test find with negative queries.
    test_vault_find(vault, "", [])
    test_vault_find(vault, "secret", [])

    # Test find with positive queries.
    test_vault_find(vault, "has some description", [('key1.long.with_desc', 0), ('key2.short.with_desc', 0)])
    test_vault_find(vault, "also", [('key2.short.with_desc', 0)])

    find_key = "find_test_key"
    descs = [ "Muh bitcoins!", "muh fight club", "Naughty club ;)" ]
    test_data[find_key] = TestRecordVersions()
    for desc in descs:
        secret = bytearray(desc.encode('utf-8'))
        test_data[find_key].add(secret, desc)
        update_kwargs = test_helper_kwargs_for_add_or_update(find_key, secret, desc)
        test_vault_update(vault, update_kwargs)

    # Test find for different search combinations across versions.
    test_vault_find(vault, "muh", [(find_key, 0), (find_key, 1)])
    test_vault_find(vault, "clb", [(find_key, 2), (find_key, 1)])
    test_vault_find(vault, "coins", [(find_key, 0)])
    test_vault_find(vault, "fiGht", [(find_key, 1)])
    test_vault_find(vault, "haughty", [(find_key, 2)])

    # Test del_version with bad args.
    test_vault_del_version_bad_args(vault, find_key, [ 0, 1, 2 ])

    # Test del_version for existing key/version combo.
    # This also tests that get fails on the combo once deleted.
    test_vault_del_version(vault, find_key, 0)
    test_data[find_key].delete(0)

    # Test find for different search combinations after deletion of version.
    test_vault_find(vault, "muh", [(find_key, 1)])
    test_vault_find(vault, "clb", [(find_key, 2), (find_key, 1)])
    test_vault_find(vault, "coins", [])
    test_vault_find(vault, "fiGht", [(find_key, 1)])
    test_vault_find(vault, "haughty", [(find_key, 2)])

    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    reloaded_vault = test_helper_reload(vault, filepath, dek, sek)

    # Test find for different search combinations after deletion of version.
    test_vault_find(reloaded_vault, "muh", [(find_key, 1)])
    test_vault_find(reloaded_vault, "clb", [(find_key, 2), (find_key, 1)])
    test_vault_find(reloaded_vault, "coins", [])
    test_vault_find(reloaded_vault, "fiGht", [(find_key, 1)])
    test_vault_find(reloaded_vault, "haughty", [(find_key, 2)])

    test_helper_check_all_existing_keys_n_vers(reloaded_vault, test_data)

    vault = reloaded_vault # Assign to the original variable to avoid copy-paste errors.
    
    # Test del_version with bad args.
    test_vault_del_version_bad_args(vault, find_key, [ 1, 2 ])

    # Test del_version for existing key - default version combo.
    # This also tests that get fails on the combo once deleted.
    test_vault_del_version(vault, find_key, None)
    find_key_default_ver = test_data[find_key].default_version()
    test_data[find_key].delete(find_key_default_ver)

    # Test find for different search combinations after deletion of version.
    test_vault_find(vault, "muh", [(find_key, 1)])
    test_vault_find(vault, "clb", [(find_key, 1)])
    test_vault_find(vault, "coins", [])
    test_vault_find(vault, "fiGht", [(find_key, 1)])
    test_vault_find(vault, "haughty", [])

    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    reloaded_vault = test_helper_reload(vault, filepath, dek, sek)

    # Test find for different search combinations after reload.
    test_vault_find(reloaded_vault, "muh", [(find_key, 1)])
    test_vault_find(reloaded_vault, "clb", [(find_key, 1)])
    test_vault_find(reloaded_vault, "coins", [])
    test_vault_find(reloaded_vault, "fiGht", [(find_key, 1)])
    test_vault_find(reloaded_vault, "haughty", [])

    test_helper_check_all_existing_keys_n_vers(reloaded_vault, test_data)

    vault = reloaded_vault # Assign to the original variable to avoid copy-paste errors.

    # Add back the first version as an update.
    desc = descs[0]
    secret = bytearray(desc.encode('utf-8'))
    test_data[find_key].add(secret, desc)
    update_kwargs = test_helper_kwargs_for_add_or_update(find_key, secret, desc)
    test_vault_update(vault, update_kwargs)

    # Test find for different search combinations after update.
    test_vault_find(vault, "muh", [(find_key, 1), (find_key, 3)])
    test_vault_find(vault, "clb", [(find_key, 1)])
    test_vault_find(vault, "coins", [(find_key, 3)])
    test_vault_find(vault, "fiGht", [(find_key, 1)])
    test_vault_find(vault, "haughty", [])

    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    reloaded_vault = test_helper_reload(vault, filepath, dek, sek)

    # Test find for different search combinations after update.
    test_vault_find(reloaded_vault, "muh", [(find_key, 1), (find_key, 3)])
    test_vault_find(reloaded_vault, "clb", [(find_key, 1)])
    test_vault_find(reloaded_vault, "coins", [(find_key, 3)])
    test_vault_find(reloaded_vault, "fiGht", [(find_key, 1)])
    test_vault_find(reloaded_vault, "haughty", [])

    test_helper_check_all_existing_keys_n_vers(reloaded_vault, test_data)

    vault = reloaded_vault # Assign to the original variable to avoid copy-paste errors.

    # Fully delete all versions of the key.
    test_vault_del_key(vault, find_key)
    del test_data[find_key]

    # Test find for different search combinations after update.
    test_vault_find(vault, "muh", [])
    test_vault_find(vault, "clb", [])
    test_vault_find(vault, "coins", [])
    test_vault_find(vault, "fiGht", [])
    test_vault_find(vault, "haughty", [])

    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    # Check retrieval for bad args ...
    nonexistent_keys = [ find_key ]
    test_vault_get_bad_args(vault, keyspecs[0][0], 0, nonexistent_keys, 1)
    test_vault_secret_bad_args(vault, keyspecs[0][0], 0, nonexistent_keys, 1)

    vault = test_helper_reload(vault, filepath, dek, sek)

    # Test find for different search combinations after update.
    test_vault_find(vault, "muh", [])
    test_vault_find(vault, "clb", [])
    test_vault_find(vault, "coins", [])
    test_vault_find(vault, "fiGht", [])
    test_vault_find(vault, "haughty", [])

    test_helper_check_all_existing_keys_n_vers(vault, test_data)

    # Check retrieval for bad args ...
    nonexistent_keys = [ find_key ]
    test_vault_get_bad_args(vault, keyspecs[0][0], 0, nonexistent_keys, 1)
    test_vault_secret_bad_args(vault, keyspecs[0][0], 0, nonexistent_keys, 1)

    # Test find with negative queries.
    test_vault_find(vault, "", [])
    test_vault_find(vault, "secret", [])

    # Test find with positive queries.
    test_vault_find(vault, "has some description", [('key1.long.with_desc', 0), ('key2.short.with_desc', 0)])
    test_vault_find(vault, "also", [('key2.short.with_desc', 0)])
    print("Journey 4: Synchronized find with version changes works.")

'''
- Journey 5:
  - For all combos of default_desc and description:
    - Add the key
    - For all combos of default_desc and description:
      - Add the key again (should fail)
      - Update the key with add_missing = False (should succeed)
      - Check that find finds the right versions.
      - Delete the latest version
    - Delete version 0
    - Add the key again (should fail)
    - Delete the key
    - Add the key
    - Update the key with a random choice of default_desc and description with add_missing = default
    - Delete version 0
    - Add the key again (should fail)
    - Delete the key
    - Add the key through update with add_missing = False (should fail)
    - Add the key through update with add_missing = True
    - For all combos of default_desc and description:
      - Add the key again (should fail)
	  - Update the key with add_missing = True (should succeed)
	  - Check that find finds the right versions.
    - Delete the key
    - Add the key
    - Delete version 0
    - Add the key again (should fail)
    - Delete the key
'''
def test_journey5():
    filepath = "/tmp/journey5.vlt"
    Path(filepath).unlink(missing_ok = True) # Remove leftover path from previous test fails.
    
    dek = SecuredAESCBC.random(g_test_vault_state['master_key'])
    sek = SecuredAESCBC.random(g_test_vault_state['master_key'])

    # Start with an empty vault.
    vault = Vault(sek)

    # Generate all combos for description
    the_desc = "Polly wants a cracker"
    cg = ComboGenerator()
    cg.add_arg('desc', [ None, "", the_desc ], [])
    cg.add_arg('default_desc', [None, True, False], [])
    good_combos, bad_combos = cg.generate_indexed_combos()

    test_key = "the key"
    for gc in good_combos:
        test_data = { test_key: TestRecordVersions() }
        kwargs_part, arg_idx = cg.make_kwargs(gc)
        secret = mutable_urandom(8)
        kwargs = test_helper_kwargs_for_add_or_update(test_key, secret, kwargs_part['desc'], kwargs_part['default_desc'])
        test_vault_add(vault, kwargs)
        test_data[test_key].add(secret, kwargs_part['desc'], kwargs_part['default_desc'])
        for gc1 in good_combos:
            kwargs_part2, arg_idx2 = cg.make_kwargs(gc1)
            secret2 = mutable_urandom(8)
            kwargs2 = test_helper_kwargs_for_add_or_update(test_key, secret2, kwargs_part2['desc'], kwargs_part2['default_desc'], add_missing = False)
            # Attempt to add again (should fail)
            test_vault_duplicate_add(vault, kwargs2)
            # Update
            test_vault_update(vault, kwargs2)
            test_data[test_key].add(secret2, kwargs_part2['desc'], kwargs_part2['default_desc'])
            # Check sanity.
            test_helper_check_all_existing_keys_n_vers(vault, test_data)
            # Find all versions which has the key as the desc...
            for find_key in [ test_key, the_desc ]:
                expected_versions = []
                for v, desc in test_data[test_key].expected_desc.items():
                    if desc is None and find_key == test_key:
                        expected_versions.append((test_key, v))
                    elif desc == find_key:
                        expected_versions.append((test_key, v))
                test_vault_find(vault, find_key, expected_versions)
            # Delete the latest version...
            latest = test_data[test_key].default_version()
            test_data[test_key].delete(latest)
            test_vault_del_version(vault, test_key, latest)
        # Now delete version 0 and check that add still fails.
        test_vault_del_version(vault, test_key, 0)
        test_data[test_key].delete(0)
        test_vault_duplicate_add(vault, kwargs)
        # Delete the key completely and try to add back.
        test_vault_del_key(vault, test_key)
        del test_data[test_key]
        kwargs = test_helper_kwargs_for_add_or_update(test_key, secret, kwargs_part['desc'], kwargs_part['default_desc'])
        test_vault_add(vault, kwargs)
        test_data[test_key] = TestRecordVersions()
        test_data[test_key].add(secret, kwargs_part['desc'], kwargs_part['default_desc'])
        # Choose a random combination to update the key...
        kwargs_part2, arg_idx2 = cg.make_kwargs(random.choice(good_combos))
        kwargs2 = test_helper_kwargs_for_add_or_update(test_key, secret2, kwargs_part2['desc'], kwargs_part2['default_desc'], add_missing = None)
        # Update
        test_vault_update(vault, kwargs2)
        test_data[test_key].add(secret2, kwargs_part2['desc'], kwargs_part2['default_desc'])
        # Check sanity.
        test_helper_check_all_existing_keys_n_vers(vault, test_data)
        # Delete version 0 again and check that add still fails.
        test_vault_del_version(vault, test_key, 0)
        test_data[test_key].delete(0)
        test_vault_duplicate_add(vault, kwargs)
        # Delete key for next set of tests ...
        test_vault_del_key(vault, test_key)
        del test_data[test_key]

        # Test update for add (add_missing = True):
        # First set add_missing = False so that actual add fails.
        kwargs = test_helper_kwargs_for_add_or_update(test_key, secret, kwargs_part['desc'], kwargs_part['default_desc'], add_missing = False)
        test_vault_update(vault, kwargs, will_fail = True)
        # Now do the actual add, which should be the default behaviour ...
        kwargs = test_helper_kwargs_for_add_or_update(test_key, secret, kwargs_part['desc'], kwargs_part['default_desc'])
        test_vault_update(vault, kwargs)
        test_data[test_key] = TestRecordVersions()
        test_data[test_key].add(secret, kwargs_part['desc'], kwargs_part['default_desc'])
        for gc1 in good_combos:
            kwargs_part2, arg_idx2 = cg.make_kwargs(gc1)
            secret2 = mutable_urandom(8)
            kwargs2 = test_helper_kwargs_for_add_or_update(test_key, secret2, kwargs_part2['desc'], kwargs_part2['default_desc'], add_missing = True)
            # Attempt to add again (should fail)
            test_vault_duplicate_add(vault, kwargs2)
            # Update
            test_vault_update(vault, kwargs2)
            test_data[test_key].add(secret2, kwargs_part2['desc'], kwargs_part2['default_desc'])
            # Check sanity.
            test_helper_check_all_existing_keys_n_vers(vault, test_data)
            # Find all versions which has the key as the desc...
            for find_key in [ test_key, the_desc ]:
                expected_versions = []
                for v, desc in test_data[test_key].expected_desc.items():
                    if desc is None and find_key == test_key:
                        expected_versions.append((test_key, v))
                    elif desc == find_key:
                        expected_versions.append((test_key, v))
                test_vault_find(vault, find_key, expected_versions)
            # Delete the latest version...
            latest = test_data[test_key].default_version()
            test_data[test_key].delete(latest)
            test_vault_del_version(vault, test_key, latest)

        # Last test: Check that without updates, deletion of version 0
        # prevents key addition...
        # Delete the key completely and try to add back.
        test_vault_del_key(vault, test_key)
        del test_data[test_key]
        kwargs = test_helper_kwargs_for_add_or_update(test_key, secret, kwargs_part['desc'], kwargs_part['default_desc'])
        test_vault_add(vault, kwargs)
        test_data[test_key] = TestRecordVersions()
        test_data[test_key].add(secret, kwargs_part['desc'], kwargs_part['default_desc'])
        # Now delete version 0 and check that add still fails.
        test_vault_del_version(vault, test_key, 0)
        test_data[test_key].delete(0)
        test_vault_duplicate_add(vault, kwargs)
        
        # Final delete of key to complete the loop...
        test_vault_del_key(vault, test_key)
        del test_data[test_key]
    print("Journey 5: All combinations of add and update of descriptions ... works!")

if __name__ == "__main__":
    test_journey1()
    test_journey2()
    test_journey3()
    test_journey4()
    test_journey5()