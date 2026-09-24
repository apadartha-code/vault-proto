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

import mmap
import ctypes

import secrets

from security.framework import SymmetricKey, XorMask, SingleUse


# Securely load the standard C library
try:
    libc = ctypes.CDLL(None)
except Exception:
    libc = ctypes.CDLL(ctypes.util.find_library('c'))


class KeyObfuscator(SymmetricKey):
    __shield_up = False
    
    @classmethod
    def shield_process(cls):
        """
        Prevent core dumps and debugger attachment.
        Perform only once per process lifecycle.
        """
        if cls.__shield_up:
            return
            
        # 1. Enforce core process protections
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0)) # Block core dumps
        if hasattr(libc, 'prctl'):
            libc.prctl(4, 0, 0, 0, 0) # Clear PR_SET_DUMPABLE (Anti-Ptrace)
        cls.__shield_up = True

    """
    Tries to hide the actual key inside memory locked pages with
    an xor mask. Kind of a shell game, to throw off memory scanners.
    Hardens the process, generates Page Noise Flooding (decoy allocations),
    allocates a structural-blind real block, and locks them all in RAM.
    Not really a standard key, because it does not return the
    encrypted value, but we can send back a fake.
    """
    def __init__(self, nkeybytes: int, decoy_count: int = 32, masker: XorMask = None):
        self._alloc_length = nkeybytes
        self._decoy_count = decoy_count
        self._decoys = []  # Tracks tuples of (mmap_obj, raw_address)
        self._masker = masker
        if masker is None:
            self._masker = XorMask() # Create a default one.

        # 2. IMPLEMENT PAGE NOISE FLOODING
        # Create identical-looking, locked decoy pages to flood the kernel's PTE map
        # We align decoy allocation sizes to system page size (typically 4096 bytes) for realism
        page_size = mmap.PAGESIZE if hasattr(mmap, 'PAGESIZE') else 4096
        allocation_size = max(self._alloc_length, page_size)

        for _ in range(self._decoy_count):
            decoy_map = mmap.mmap(
                -1, 
                allocation_size,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE
            )
            decoy_address = ctypes.addressof(ctypes.c_char.from_buffer(decoy_map))
            
            # Fill decoys with flat, realistic-looking mask noise to blend entropy profiles
            decoy_noise = secrets.token_bytes(allocation_size)
            decoy_map.write(decoy_noise)
            
            # Pinned via mlock so it gets the exact same kernel PTE flags as the real secret
            if hasattr(libc, 'mlock'):
                libc.mlock(decoy_address, allocation_size)
                
            self._decoys.append((decoy_map, decoy_address, allocation_size))

        # 3. Allocate the REAL structural-blind Ghost Memory block
        self._ghost_map = mmap.mmap(
            -1, 
            self._alloc_length,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE
        )
        self._address = ctypes.addressof(ctypes.c_char.from_buffer(self._ghost_map))

        # Lock the real page
        if hasattr(libc, 'mlock'):
            libc.mlock(self._address, self._alloc_length)
    
    def encrypt(self, wrapped_plain: SingleUse) -> bytearray:
        # 4. Mask the real secret and copy it into the ghost allocation
        mask_seed = secrets.randbits(31)
        with wrapped_plain.revealed() as plainbytes:
            masked_bytes = self._masker.apply(plainbytes, mask_seed)
        ctypes.memmove(self._address, ctypes.c_char_p(bytes(masked_bytes)), self._alloc_length)
        return bytearray(mask_seed.to_bytes(4, byteorder='big'))
    
    def decrypt(self, cipherbytes: bytearray) -> SingleUse:
        """Temporarily extracts and unmasks the data for crypto actions."""
        if self._ghost_map is None:
            raise ValueError("Buffer has been securely destroyed.")
        raw_masked = bytearray(self._ghost_map[:])
        mask_seed = int.from_bytes(cipherbytes, byteorder='big')
        return SingleUse(self._masker.apply(raw_masked, mask_seed))

    def clear(self):
        """Tears down the entire infrastructure: wipes real data and all decoy pages."""
        # A. Clear the real secret ghost block
        if self._ghost_map is not None:
            try:
                if hasattr(libc, 'memset'):
                    ctypes.memset(self._address, 0, self._alloc_length)
                self._ghost_map.write(secrets.token_bytes(self._alloc_length))
            finally:
                if hasattr(libc, 'munlock'):
                    libc.munlock(self._address, self._alloc_length)
                self._ghost_map.close()
                self._ghost_map = None
                self._address = None

        # B. Clear the entire page flood array (Decoys)
        for decoy_map, decoy_address, alloc_size in self._decoys:
            try:
                if hasattr(libc, 'memset'):
                    ctypes.memset(decoy_address, 0, alloc_size)
            finally:
                if hasattr(libc, 'munlock'):
                    libc.munlock(decoy_address, alloc_size)
                decoy_map.close()
        
        self._decoys.clear()

    def __del__(self): self.clear()