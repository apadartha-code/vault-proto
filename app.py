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
import sys
import time
import argparse
from pathlib import Path
import uuid
import base64
import random
from flask import Flask, request, jsonify, render_template, session

import traceback

from security.aeshelper import AESCBC, SecuredAESCBC, SecuredAESGCM
from security.framework import SingleUse, EncryptedSecret
from security.utils import derive_key
from security.obfuscate import KeyObfuscator
from crypto import read_password_via_syscall, read_secret_from_fifo, mutable_urandom, TransCrypter
from sessions import SessionState, Sessions, KMSessionsIface
from vault import VaultManager, VaultMetaKey

# Import the tool package blueprint
from keymaker_ui import keymaker_bp, KeymakerSessions

app = Flask(__name__)
app.secret_key = os.urandom(24) # Shared backend cookie verification identity
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Mount the Keymaker tool workspace under /keymaker prefix
app.register_blueprint(keymaker_bp, url_prefix='/keymaker')

# Declare the global master key here.
master_key = None

# Global session store...
g_sessions = Sessions()
# Register it with the keymaker UI module.
KeymakerSessions.set(KMSessionsIface(g_sessions))


# The platform index (The core verification dashboard wrapper)
@app.route('/')
def main_application_dashboard():
    # Every access creates a new session...
    session_id = session.pop(Sessions.SESSION_KEY, None)
    if session_id:
        # Clear out the old session details.
        g_sessions.purge(session_id)
    session_id = g_sessions.new(Sessions.SESS_TYPE_ADMIN)
    session[Sessions.SESSION_KEY] = session_id
    return render_template('index.html', app_session_id=session_id)

@app.route('/keymaker_done')
def keymaker_done():
    return render_template('keymaker_done.html')

@app.route("/api/encoding", methods=['POST', 'GET'])
def get_encoding():
    session_id = session[Sessions.SESSION_KEY]
    session_state = g_sessions.get(session_id)
    transcoder = g_sessions.get(session_id).get_transcrypter()
    if not transcoder:
        return jsonify({"error": "No transcoder has been set up for the session yet."}), 500
    
    if request.method == 'GET':
        # Read raw output securely dropped inside backend session memory by the tool blueprint
        verified_encoding = ""
        try:
            wrapper = None
            if session_state.has_obj(SessionState.SECONDARY_ENCODING):
                wrapper = session_state.get_obj(SessionState.SECONDARY_ENCODING, is_secret = True)
            elif session_state.has_obj(SessionState.PRIMARY_ENCODING):
                wrapper = session_state.get_obj(SessionState.PRIMARY_ENCODING, is_secret = True)
            if wrapper:
                verified_encoding = transcoder.encode(wrapper.get())
        except Exception as e:
            print("Error:", str(e))
            return jsonify({"error": "Retrieval failed"}), 500

        return jsonify({"encoding": verified_encoding }), 200

    elif request.method == 'POST':
        data = request.get_json() or {}
        # We are trying to set the primary metakey.
        if session_state.has_obj(SessionState.PRIMARY_ENCODING):
            return jsonify({"error": "Key already set for session."}), 500
        # Get the key...
        encoded_key = data.get('encoding')
        if not encoded_key:
            return jsonify({"error": "No key in request."}), 500
        # The key must be associated with a vault.
        try:
            metakey = VaultMetaKey(transcoder.decode(encoded_key), master_key)
            if not VaultManager.get().exists_key(metakey):
                return jsonify({"error": "Key is not associated with any vault."}), 500
            session_state.set_obj(SessionState.PRIMARY_ENCODING, metakey.get(), is_secret = True)
        except ValueError as ve:
            return jsonify({"error": "Could not process key."}), 500
    
        return jsonify({
            'status': 'redirect',
            'redirect_url': '/access'
        }), 200

@app.route("/api/vault", methods=['POST'])
def handle_vault_API():
    data = request.get_json() or {}
    session_id = data.get('session-id')
    try:
        session_state = g_sessions.get(session_id)
    except KeyError as ke:
        return jsonify({
            'status': 'error',
            'msg': 'Session does not exist.'
        }), 404
    # Check that the session is alive and not expired.
    valid_session = False
    if session_state.has_obj(SessionState.VALIDITY):
        expiry = session_state.get_obj(SessionState.VALIDITY)
        if expiry > time.time():
            # Check that it's an API session.
            if session_state.get_obj(Sessions.SESSION_TYPE) == Sessions.SESS_TYPE_API:
                valid_session = True
    if not valid_session:
        return jsonify({
            'status': 'error',
            'msg': 'Expired or invalid session.'
        }), 401

    # So, we have a valid session. It should have an associated vault.
    vault_id = session_state.get_obj(SessionState.VAULT_ID)
    try:
        vault = VaultManager.get().get_vault(vault_id)
    except KeyError as ke:
        return jsonify({
            'status': 'error',
            'msg': 'Session does not have an opened vault.'
        }), 500

    # Extract the permissions...
    readonly = session_state.get_obj(SessionState.READONLY) is True

    # Find out the operation ...
    op = data.get("operation")
    if op is None:
        return jsonify({
            'status': 'error',
            'msg': 'Request object is missing the field _operation_.'
        }), 400
    if readonly and op in [ "add", "update", "delete" ]:
        return jsonify({
            'status': 'error',
            'msg': 'Session is read-only'
        }), 403

    # Get the arguments dict ...
    op_args = data.get("arguments", {})
    record_key = op_args.get('key')

    # Get the transcrypter ready and process the secret if present in args.
    transcoder = session_state.get_transcrypter()
    secret_b64 = op_args.get('secret')
    record_secret = None
    if secret_b64:
        record_secret = transcoder.decode(secret_b64) # Get a SingleUse object.

    try:
        if op == "add":
            kwargs = {
                'key': record_key,
                'wrapped_secret': record_secret
            }
            desc = op_args.get("description")
            if desc:
                kwargs['desc'] = desc
            default_desc = op_args.get("default-description")
            if default_desc:
                kwargs['default_desc'] = default_desc
            vault.add(**kwargs)
            VaultManager.get().save_vault(vault_id)
            return jsonify({ 'status': "success" }), 200
        elif op == "versions":
            response = vault.versions(record_key)
            return jsonify({ 'status': "success", 'response': response }), 200
        elif op == "get":
            version = op_args.get("version")
            kwargs = { 'key': record_key }
            if version:
                kwargs['version'] = version
            record = vault.get(**kwargs)
            return jsonify({ 'status': "success", 'response': record.as_dict() }), 200
        elif op == "find":
            kwargs = { 'query': op_args.get("query") }
            max_count = op_args.get("count")
            if max_count:
                kwargs['max_count'] = max_count
            response = vault.find(**kwargs)
            return jsonify({ 'status': "success", 'response': response }), 200
        elif op == "secret":
            version = op_args.get("version")
            kwargs = { 'key': record_key }
            if version:
                kwargs['version'] = version
            wrapped_secret = vault.secret(**kwargs)
            # return jsonify({ 'status': "success", 'response': transcoder.encode(wrapped_secret) }), 200
            result = transcoder.encode(wrapped_secret)
            return jsonify({ 'status': "success", 'response': result }), 200
        elif op == "update":
            kwargs = {
                'key': record_key,
                'wrapped_secret': record_secret
            }
            desc = op_args.get("description")
            if desc:
                kwargs['desc'] = desc
            default_desc = op_args.get("default-description")
            if default_desc:
                kwargs['default_desc'] = default_desc
            add_missing = op_args.get("add-missing")
            if add_missing:
                kwargs['add_missing'] = add_missing
            vault.update(**kwargs)
            VaultManager.get().save_vault(vault_id)
            return jsonify({ 'status': "success" }), 200
        elif op == "delete":
            all_version = op_args.get("all-versions")
            version = op_args.get("version")
            if all_version and version is not None:
                # It's either/or - both cannot be set.
                return jsonify({
                    'status': "error",
                    'msg': "Invalid argument combination."
                }), 400
            elif all_version:
                vault.del_key(record_key)
                VaultManager.get().save_vault(vault_id)
                return jsonify({ 'status': "success" }), 200
            elif version is not None:
                vault.del_version(record_key, version)
                VaultManager.get().save_vault(vault_id)
                return jsonify({ 'status': "success" }), 200
            else:
                # Neither is specified. There is no default ...
                return jsonify({
                    'status': "error",
                    'msg': "Missing arguments for delete scope."
                }), 400
        else:
            return jsonify({
                'status': "error",
                'msg': "Unknown operation {}.".format(op)
            }), 400
    except KeyError as ke:
        err_str = str(ke)
        print("ERROR: {}".format(err_str))
        return jsonify({
            'status': "error",
            'msg': "Non-existent key or version"
        }), 404
    except Exception as e:
        err_str = str(e)
        print("ERROR: {}".format(err_str))
        traceback.print_exc()
        return jsonify({
            'status': "error",
            'msg': "Operation failed: " + err_str
        }), 501

@app.route("/api/otp", defaults={'otp_hash': None}, methods=['POST'])
@app.route('/api/otp/<string:otp_hash>', methods=['POST'])
def handle_OTP(otp_hash):
    if request.method == 'POST':
        data = request.get_json() or {}
        if otp_hash is None:
            # Create a new OTP.
            session_id = session[Sessions.SESSION_KEY]
            session_state = g_sessions.get(session_id)

            if not session_state.has_obj(SessionState.VAULT_ID):
                return jsonify({
                    'status': 'error',
                    'msg': "No open vault exists for session."
                }), 500

            duration = data.get('duration', Sessions.DEFAULT_SESS_DURATION)
            readonly = data.get('readonly', True)
            otp_expiry = Sessions.OTP_EXPIRY
            try:
                wrapped_otp = g_sessions.new_otp(session_id, duration, otp_expiry = otp_expiry, readonly = readonly)
            except RuntimeError as re:
                return jsonify({
                    'status': 'error',
                    'msg': "OTP generation is temporarily disabled. Try again after some time."
                }), 403
            except AttributeError as ae:
                return jsonify({
                    'status': 'error',
                    'msg': "Non admin session does not have OTP generation permission."
                }), 401
            except Exception as e:
                print("ERROR: Failed to generate OTP:", str(e), file = sys.stderr)
                return jsonify({
                    'status': 'error',
                    'msg': "OTP generation failed."
                }), 500

            encoded_otp = session_state.get_transcrypter().encode(wrapped_otp)
            return jsonify({
                'status': 'success',
                'otp': encoded_otp,
                'expiry': otp_expiry
            }), 200
        else:
            # Create a new API session.
            salt = data.get('salt') # Base 64 for challenge
            response = g_sessions.new_app_session(otp_hash, salt)
            if 'error' in response:
                return jsonify(response), 404
            return jsonify(response), 200

def get_session_state_vars(session_state):
    """
    Returns the triplet:
    - Vault ID for any open vault for the session.
    - Primary key as a VaultMetaKey, if any.
    - Secondary key as a VaultMetaKey, if any.
    """
    sess_vault_id = None
    metakey = None
    second_metakey = None
    
    if session_state.has_obj(SessionState.VAULT_ID):
        # Session has an open vault.
        sess_vault_id = session_state.get_obj(SessionState.VAULT_ID)

    if session_state.has_obj(SessionState.PRIMARY_ENCODING):
        wrapped_keybytes = session_state.get_obj(SessionState.PRIMARY_ENCODING, is_secret = True)
        metakey = VaultMetaKey(wrapped_keybytes.get(), master_key)
    if session_state.has_obj(SessionState.SECONDARY_ENCODING):
        wrapped_keybytes = session_state.get_obj(SessionState.SECONDARY_ENCODING, is_secret = True)
        second_metakey = VaultMetaKey(wrapped_keybytes.get(), master_key)

    return (sess_vault_id, metakey, second_metakey)

@app.route('/vault', methods=['POST', 'PUT'])
def handle_vault_UI():
    session_id = session[Sessions.SESSION_KEY]
    data = request.get_json() or {}
    session_state = g_sessions.get(session_id)

    sess_vault_id, metakey, second_metakey = get_session_state_vars(session_state)
    
    action = data.get('action')
    vault_mgr = VaultManager.get()
    if action == "create":
        if not metakey:
            # Key itself does not exist.
            raise ValueError("Session does not have a meta key for vault.")
        # Meta key is not associated with any vault.
        if vault_mgr.exists_key(metakey):
            # Vault is already created.
            raise RuntimeError("Vault already exists for session meta key.")
        else:
            vault_mgr.create_vault(metakey)
            return jsonify({
                'status': 'redirect',
                'redirect_url': '/access'
            }), 200
    elif action == "open":
        if not metakey:
            # Key itself does not exist.
            raise ValueError("Session does not have a meta key for vault.")
        # Meta key is associated with a vault.
        if not vault_mgr.exists_key(metakey):
            # Vault does not exist.
            raise RuntimeError("No vault exists for session meta key. Create one first.")
        else:
            # Get the vault id from the key.
            key_vault_id, dek, sek = vault_mgr.metadata(metakey)
            if sess_vault_id is not None and key_vault_id != sess_vault_id:
                # Should fail if an alternate vault is already open.
                raise RuntimeError("Vault mapped to the key is different from the one already open in current session.")
            # Extract the password.
            wrapped_vault_passwd = session_state.get_transcrypter().decode(data.get('password'))
            if not wrapped_vault_passwd:
                raise ValueError("Vault password cannot be empty.")
            vault_passwd = EncryptedSecret(master_key, wrapped_plain = wrapped_vault_passwd)
            vaultid = vault_mgr.open_vault(metakey, vault_passwd)
            if not vaultid:
                raise RuntimeError("Failed to open vault.")
            session_state.set_obj(SessionState.VAULT_ID, vaultid)
            return jsonify({
                'status': 'redirect',
                'redirect_url': '/access'
            }), 200
    elif action == "set":
        # Set up the vault based on a password.
        # If the session already has the vault set, just validate the password for access.
        
        # Extract the password.
        wrapped_vault_passwd = session_state.get_transcrypter().decode(data.get('password'))
        if not wrapped_vault_passwd:
            raise ValueError("Vault password cannot be empty.")
        vault_passwd = EncryptedSecret(master_key, wrapped_plain = wrapped_vault_passwd)
    
        if session_state.has_obj(SessionState.VAULT_ID):
            # Validate password for the vault opened in the session.
            vaultid = session_state.get_obj(SessionState.VAULT_ID)
            if vault_mgr.verify_passwd(vaultid, vault_passwd):
                return jsonify({
                    'status': 'redirect',
                    'redirect_url': '/manage'
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': "Invalid password for session vault."
                }), 401
        
        # Session does not have a vault.
        # Check if the password at all matches any vault...
        vaultid = vault_mgr.find_by_passwd(vault_passwd)
        if not vaultid:
            return jsonify({
                'status': 'error',
                'message': "Could not find vault to attach for session."
            }), 403
        
        session_state.set_obj(SessionState.VAULT_ID, vaultid)
        return jsonify({
            'status': 'redirect',
            'redirect_url': '/manage'
        }), 200
    elif action == "attach_key":
        if not second_metakey:
            # New key itself does not exist.
            raise ValueError("Session does not have a meta key to attach to vault.")
        if sess_vault_id is None:
            # There is no vault in the session to attach to...
            raise ValueError("Session does not have any open vault to attach a new key.")
        # Second meta key should not be associated with any vault.
        if vault_mgr.exists_key(second_metakey):
            # Vault is already created.
            raise RuntimeError("Vault already exists for new key to be attached.")
        else:
            vault_mgr.attach_vault(second_metakey, sess_vault_id)
            return jsonify({
                'status': 'redirect',
                'redirect_url': '/access'
            }), 200
    else:
        raise NotImplementedError("Unhandled action: {}".format(action))

'''
- Session vault open
  - Secondary key exists
    ! Secondary key file exists: Error - erase secondary key / go to self
    . Secondary key file does not exist: attach
  > Secondary key does not exist: access
- Session vault not open
  (Allow for password if any vault is open in any other session)
  - Primary key exists
    . Primary key file exists: open/reopen
	. Primary key file does not exist: create
  > Primary key does not exist: access
'''
def access_action(sess_vault_id, metakey, second_metakey):
    vault_mgr = VaultManager.get()
    msg = ""
    next_action = ""
    if sess_vault_id:
        if second_metakey:
            if vault_mgr.exists_key(second_metakey):
                # This is an error, irrespective of whether the second metakey
                # points to the same vault.
                next_action = "delete_2nd_key"
                msg = "We encountered an erronous state involving the secondary key, which has been deleted. Please try again."
            else:
                next_action = "attach_key"
        else:
            # This should be the normal state...
            # The vault for the primary key is open and no second key present.
            next_action = "access"
    else:
        if metakey:
            if vault_mgr.exists_key(metakey):
                next_action = "open"
            else:
                next_action = "create"
        else:
            # We don't have an open vault, nor we have a metakey.
            # Attach a vault.
            next_action = "attach"
    return next_action, msg
    
@app.route("/access")
def show_access():
    session_id = session[Sessions.SESSION_KEY]
    session_state = g_sessions.get(session_id)

    sess_vault_id, metakey, second_metakey = get_session_state_vars(session_state)
    # TBD: Show the message in the template.
    next_action, msg = access_action(sess_vault_id, metakey, second_metakey)
    if next_action == "delete_2nd_key":
        session_state.del_obj(SessionState.SECONDARY_ENCODING)
        next_action, _ = access_action(sess_vault_id, metakey, None)

    if next_action in [ 'open', 'create', 'attach_key' ]:
        return render_template('result.html', next_action=next_action)
    elif next_action not in [ "access", "attach" ]:
        raise RuntimeError("Unhandled access action {} encountered.".format(next_action))

    # So, finally we come to actual access.
    show_passwd_input = True # Default for access
    hide_key_input = True # Default for access
    if next_action == "attach":
        show_passwd_input = VaultManager.get().has_open_vaults()
        hide_key_input = False
    return render_template(
        'access.html',
        resource_open=show_passwd_input,
        access_key_set=hide_key_input
    )
    
@app.route("/manage")
def show_manage():
    session_id = session[Sessions.SESSION_KEY]
    session_state = g_sessions.get(session_id)

    sess_vault_id, metakey, second_metakey = get_session_state_vars(session_state)
    return render_template('manage.html', attach_key_disabled = sess_vault_id is None)

@app.route("/challenge", methods=["POST"])
def handle_challenge():
    """
    Respond with a plaintext and encrypted (with the server startup
    nonce) version of the server UUID. The requestor can use their
    own password and salt to decrypt and match. Also send a random
    32-byte (base64 encoded) string to be used as a session password,
    encoded with the same key.
    """
    data = request.get_json() or {}
    client_salt_b64 = data.get("salt")
    if not client_salt_b64:
        return jsonify({"error": "Missing parameters"}), 400

    aesalgo = AESCBC()
    plaintext = app.config["SERVER_UUID"]
    try:
        salt = base64.b64decode(client_salt_b64)
        session_secret = SecuredAESGCM.random(master_key)
        with derive_key(app.config["STARTUP_PASSWORD"].get(), salt).revealed() as derived_key:
            cipherbytes = aesalgo.encrypt(derived_key, SingleUse(bytearray(plaintext.encode())))
            cipherbytes2 = aesalgo.encrypt(derived_key, session_secret.get())
        # Create a TransCrypter and attach it to the session
        # for the blueprint to use when it's invoked.
        encoding_helper = TransCrypter(session_secret, mask_seed = random.randint(0, 2**64))
        session_id = session[Sessions.SESSION_KEY]
        # For communicating with the frontend and saving the final encoding.
        g_sessions.get(session_id).set_transcrypter(encoding_helper)

        return jsonify({
            "iv": base64.b64encode(cipherbytes[:16]).decode('utf-8'),
            "ciphertext": base64.b64encode(cipherbytes[16:]).decode('utf-8'),
            "iv2": base64.b64encode(cipherbytes2[:16]).decode('utf-8'),
            "ciphertext2": base64.b64encode(cipherbytes2[16:]).decode('utf-8'),
            "plaintext": plaintext
        }), 200
    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": "Processing failed"}), 500

if __name__ == '__main__':

    # Dynamically locate the folder where main.py actually lives
    src_root = os.path.dirname(os.path.abspath(__file__))
    # project_root = os.path.join(src_root, "..")
    project_root = src_root
    # For now, use the project root as the current working directory.
    os.chdir(project_root)
    # TBD: Run directory should be the one where the app is started,
    # unless overridden in the command line args. This affects:
    # venv, dependencies, config, data, uploads, etc... everything
    # that is impacted by setup.sh.
    run_root = os.getcwd()

    parser = argparse.ArgumentParser(
        description="Process visual cognition to binary encoding."
    )

    # Optional FIFO path argument with NO default value
    parser.add_argument(
        "--fifo-path", "-f",
        type=str,
        help="Path to the named pipe/FIFO for docker containers to read startup nonce. If omitted, reads from standard input instead."
    )

    args = parser.parse_args()

    # 1. Create the session master key that will keep everything else encrypted.
    master_key = SecuredAESCBC.random(KeyObfuscator(SecuredAESCBC.KEYBYTES))
    g_sessions.set_master_key(master_key)
    # Note! Do not put this under some app.config key,
    # because that makes it easily discoverable by
    # memory scanning for the key text.

    # 2. Get the session secret nonce for server validation.
    print("=== Secure Startup Initialization ===")
    secret_input = None
    try:
        # Branching Logic: If a path is provided, read from the FIFO
        if args.fifo_path is not None:
            # Pre-flight validation checks for the FIFO path
            if not os.path.exists(args.fifo_path):
                print(f"Error: Path '{args.fifo_path}' does not exist.", file=sys.stderr)
                sys.exit(1)

            fpath = Path(args.fifo_path)
            if not fpath.is_fifo():
                print(f"Error: Path '{args.fifo_path}' is not a valid FIFO device.", file=sys.stderr)
                sys.exit(1)

            secret_input = read_secret_from_fifo(args.fifo_path)

        # Fallback Logic: Default to your custom stdin syscall function
        else:
            secret_input = read_password_via_syscall("Enter the server verification password: ")

        # print(f"Successfully read secret ({len(secret)} bytes). Processing data...")
    except Exception as e:
        print(f"Runtime error encountered: {e}", file=sys.stderr)
        sys.exit(1)

    if len(secret_input) == 0:
        print("Error: Password cannot be empty. Aborting startup.", file = sys.stderr)
        exit(1)

    app.config["STARTUP_PASSWORD"] = EncryptedSecret(master_key, wrapped_plain = secret_input)

    # 3. Start the server.
    app.config["SERVER_UUID"] = uuid.uuid4().hex
    print("Server identity initialized. Starting HTTPS server...")

    statepath = os.path.join(run_root, VaultManager.DEFAULT_STORE)
    VaultManager.setup(statepath) # Set up the singleton for vaults.

    cfg_path = os.path.join(run_root, "config")
    print("DEBUG: Using config path:", cfg_path)
    cert_path = os.path.join(cfg_path, "cert.pem")
    key_path = os.path.join(cfg_path, "key.pem")
    # app.run(host='0.0.0.0', port=5000, ssl_context=('config/cert.pem', 'config/key.pem'))
    app.run(host='0.0.0.0', port=5000, ssl_context=(cert_path, key_path))