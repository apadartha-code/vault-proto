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

import abc
from typing import Generator, List, Union
from contextlib import contextmanager

import secrets

from security.native import mutable_md5

'''
An abstract class containing an sensitive secret providing a context
within which the secret can be temporarily revealed and ensuring that
the plaintext is wiped from memory afterwards.
'''
class WipeableSecret(abc.ABC):
    def __init__(self, sensitive_bytes: Union[bytes, bytearray]):
        secret = sensitive_bytes
        if isinstance(secret, bytes):
            secret = bytearray(sensitive_bytes)
        if not isinstance(secret, bytearray):
            raise TypeError("Input must be a mutable bytearray.")
        self._secret = secret

    @abc.abstractmethod
    def _unmask(self) -> bytearray:
        raise NotImplementedError("_unmask method needs to be overriden to suit the specific key mechanism.")

    @contextmanager
    def revealed(self) -> Generator[bytearray, None, None]:
        """
        Context manager that fetches the decrypted bytearray, yields it for use,
        and guarantees its contents are zeroed out immediately afterward.
        """
        unmasked_bytes = self._unmask()
        try:
            yield unmasked_bytes
        finally:
            # Overwrite every byte in the bytearray with zero to clear it from memory
            for i in range(len(unmasked_bytes)):
                unmasked_bytes[i] = 0

    def clear(self):
        if hasattr(self, '_secret'):
            self._secret[:] = b'\x00' * len(self._secret)

    def __len__(self):
        return len(self._secret)
    
    # TBD: Need to reconcile the utility of this method vs clear.
    def _secure_zero_mutable(self, obj: bytearray):
        """Safely zeros out mutable buffers without any pointer offset calculations."""
        length = len(obj)
        if length == 0:
            return
        buffer_address = ctypes.c_char.from_buffer(obj)
        ctypes.memset(ctypes.byref(buffer_address), 0, length)


'''
A derived class that can hold an unencrypted secret in a wipeable
context. Not meant for long duration residence in memory... only
for ensuring wipeability in a local context!
**Note:** Wipes the input clean!
'''
class WipeableTemp(WipeableSecret):
    def __init__(self, sensitive_bytes: bytearray, max_use = 1):
        if not isinstance(sensitive_bytes, bytearray):
            raise TypeError("Input must be a mutable bytearray.")
        if max_use <= 0:
            raise ValueError("Must set a positive count of uses. Defaults to 1.")
        super().__init__(sensitive_bytes.copy())
        self.__use = max_use
        sensitive_bytes[:] = b'\x00' * len(sensitive_bytes)

    def _unmask(self) -> bytearray:
        self.__use -= 1
        if self.__use < 0:
            raise RuntimeError("Maximum count of unmasking exceeded.")
        copy_of_secret = self._secret.copy()
        if self.__use == 0:
            self.clear()
        return copy_of_secret

    @classmethod
    def concat(cls, *args: List[Union[bytes, bytearray]]) -> WipeableTemp:
        output = bytearray()
        for component in args:
            if isinstance(component, bytes):
                output.extend(bytearray(component))
            else:
                output.extend(component)
        if len(output) == 0:
            raise ValueError("Concatenation produced zero-length data.")
        return cls(output)

    def __del__(self):
        self.clear()


'''
Make the usability count of a WipeableTemp explicit.
This is probably the only use case, while the general case
stays feasible.
'''
class SingleUse(WipeableTemp):
    def __init__(self, sensitive_bytes: bytearray):
        super().__init__(sensitive_bytes)

    def debug_dump(self, context: str):
        print("DEBUG: Context: \"{}\":".format(context), self._secret)


'''
An abstract class denoting a symmetric key interface.
'''
class SymmetricKey(abc.ABC):
    @abc.abstractmethod
    def encrypt(self, wrapped_plain: SingleUse) -> bytes:
        raise NotImplementedError("encrypt method needs to be overriden to suit the specific key mechanism.")
    
    @abc.abstractmethod
    def decrypt(self, cipherbytes: bytearray) -> SingleUse:
        raise NotImplementedError("decrypt method needs to be overriden to suit the specific key mechanism.")


'''
An abstract class denoting a symmetric key implementation.
'''
class SymmetricKeyAlgo(abc.ABC):
    @abc.abstractmethod
    def encrypt(self, key: bytearray, wrapped_plain: SingleUse) -> bytes:
        raise NotImplementedError("encrypt method needs to be overriden to suit the specific key mechanism.")
    
    @abc.abstractmethod
    def decrypt(self, key: bytearray, cipherbytes: bytearray) -> SingleUse:
        raise NotImplementedError("decrypt method needs to be overriden to suit the specific key mechanism.")


class EncryptedSecret:
    def __init__(self, key: SymmetricKey, wrapped_plain: SingleUse = None, other: EncryptedSecret = None):
        # Ensure that exactly one form of data is present
        if wrapped_plain and other:
            raise ValueError("Cannot use both unencrypted and encrypted data to instantiate.")
        elif wrapped_plain:
            encrypted_secret = key.encrypt(wrapped_plain)
        elif other:
            encrypted_secret = other.export(key)
        else:
            # Neither are available.
            raise ValueError("Need to provide atleast the unencrypted bytearray or another encrypted secret to instantiate.")
        self._secret = encrypted_secret
        self._key = key

    def get(self) -> SingleUse:
        """Return the plain bytes wrapped in a SingleUse"""
        # TBD: We need to simplify once we change decrypt to
        # return the SingleUse object in future.
        return self._key.decrypt(self._secret)

    def export(self, other_key: SymmetricKey) -> bytearray:
        return other_key.encrypt(self.get())

    def md5(self) -> bytearray:
        with self.get().revealed() as plainbytes:
            md5 = mutable_md5(plainbytes)
        return md5


class SecuredSymmetricKey(EncryptedSecret, SymmetricKey):
    def __init__(self, parentkey: SymmetricKey, keyalgo: SymmetricKeyAlgo, wrapped_key: SingleUse = None, other: EncryptedSecret = None):
        super().__init__(parentkey, wrapped_plain = wrapped_key, other = other)
        self._algo = keyalgo

    def encrypt(self, wrapped_plain: SingleUse) -> bytes:
        with self.get().revealed() as key:
            return self._algo.encrypt(key, wrapped_plain)

    def decrypt(self, cipherbytes: bytearray) -> SingleUse:
        with self.get().revealed() as key:
            return self._algo.decrypt(key, cipherbytes)

    # We can get better efficiency by processing encrypt or decrypt
    # multiple times per reveal...
    def encrypt_collection(self, collection: List[SingleUse]) -> List[bytearray]:
        encrypted_collection = []
        with self.get().revealed() as key:
            for item in collection:
                encrypted_collection.append(self._algo.encrypt(key, item))
        return encrypted_collection

    def decrypt_collection(self, collection: List[bytearray]) -> List[SingleUse]:
        decrypted_collection = []
        with self.get().revealed() as key:
            for item in collection:
                decrypted_collection.append(self._algo.decrypt(key, item))
        return decrypted_collection


class XorMask:
    # TBD: Consider whether we can use an object's address as a seed!
    """An utility class for masking secrets. Not really a key"""
    DEFAULT_COEFF1 = 1103515245
    DEFAULT_COEFF2 = 12345

    def __init__(self, coeff1: int = DEFAULT_COEFF1, coeff2: int = DEFAULT_COEFF2):
        self.__coeff1 = coeff1
        self.__coeff2 = coeff2

    def apply(self, data: bytearray, key_seed: int) -> bytearray:
        """Applies an in-place XOR mask to flatten the entropy signature."""
        state = key_seed
        masked = bytearray(len(data))
        for i in range(len(data)):
            state = (self.__coeff1 * state + self.__coeff2) & 0x7fffffff
            mask_byte = (state >> 16) & 0xFF
            masked[i] = data[i] ^ mask_byte
        return masked

    def random_mask(self, data: bytearray) -> bytearray:
        return self.apply(data, secrets.randbelow(2**64))
