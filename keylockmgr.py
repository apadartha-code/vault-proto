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

import threading
import time
from contextlib import contextmanager

class BaseLockManager:
    """A clean, robust Read-Write Lock Manager with writer priority and timeouts."""
    def __init__(self):
        self._pool_lock = threading.Lock()
        self._states = {}  # Maps identifier -> LockState
        self._persistent_ids = set() # IDs which are never cleaned up.

    class LockState:
        def __init__(self):
            self.condition = threading.Condition(threading.Lock())
            self.active_readers = 0
            self.waiting_writers = 0
            self.active_writers = 0
            self.ref_count = 0

        def can_read(self) -> bool:
            return self.active_writers == 0 and self.waiting_writers == 0

        def can_write(self) -> bool:
            return self.active_readers == 0 and self.active_writers == 0

    def _should_cleanup(self, identifier, state) -> bool:
        """Hook for derived classes to alter key garbage collection behavior."""
        if identifier in self._persistent_ids:
            return False
        return state.ref_count == 0

    def _acquire_state(self, identifier, exists_ok = True):
        with self._pool_lock:
            if identifier not in self._states:
                self._states[identifier] = self.LockState()
            elif exists_ok is False:
                raise KeyError(f"Identifier {identifier} already exists.")
            state = self._states[identifier]
            state.ref_count += 1
            return state

    def _release_state(self, identifier, state):
        with self._pool_lock:
            state.ref_count -= 1
            if self._should_cleanup(identifier, state) and identifier in self._states:
                del self._states[identifier]

    def persistent_id(self, identifier):
        if identifier not in self._persistent_ids:
            self._acquire_state(identifier, exists_ok = False)
            self._persistent_ids.add(identifier)

    @contextmanager
    def shared_lock(self, identifier, timeout=None):
        """Acquires a shared (read) lock. Honors timeouts perfectly."""
        state = self._acquire_state(identifier)
        acquired = False
        with state.condition:
            if timeout is not None:
                end_time = time.time() + timeout
                while not state.can_read():
                    remaining = end_time - time.time()
                    if remaining <= 0 or not state.condition.wait(remaining):
                        break
                acquired = state.can_read()
            else:
                while not state.can_read():
                    state.condition.wait()
                acquired = True

            if acquired:
                state.active_readers += 1
        try:
            yield acquired
        finally:
            if acquired:
                with state.condition:
                    state.active_readers -= 1
                    if state.active_readers == 0:
                        state.condition.notify_all()
            self._release_state(identifier, state)

    @contextmanager
    def exclusive_lock(self, identifier, timeout=None):
        """Acquires an exclusive (write) lock. Honors timeouts perfectly."""
        state = self._acquire_state(identifier)
        acquired = False
        with state.condition:
            state.waiting_writers += 1
            try:
                if timeout is not None:
                    end_time = time.time() + timeout
                    while not state.can_write():
                        remaining = end_time - time.time()
                        if remaining <= 0 or not state.condition.wait(remaining):
                            break
                    acquired = state.can_write()
                else:
                    while not state.can_write():
                        state.condition.wait()
                    acquired = True

                if acquired:
                    state.active_writers += 1
            finally:
                state.waiting_writers -= 1
        try:
            yield acquired
        finally:
            if acquired:
                with state.condition:
                    state.active_writers -= 1
                    state.condition.notify_all()
            self._release_state(identifier, state)


class HierarchicalLockManager(BaseLockManager):
    """Derived manager that layers a pseudo-key global lock above local key locks."""
    GLOBAL_KEY = "__GLOBAL_GATEKEEPER__"

    def __init__(self):
        super().__init__()
        # Pre-seed the global pseudo-key lock so it always exists
        # self._acquire_state(self.GLOBAL_KEY)
        self.persistent_id(self.GLOBAL_KEY)

    @contextmanager
    def checkpoint_lock(self, timeout=None):
        """Checkpoints act as a shared (read) lock at the global level."""
        with self.shared_lock(self.GLOBAL_KEY, timeout=timeout) as acquired:
            yield acquired

    @contextmanager
    def read_lock(self, key, timeout=None):
        """Local readers identify as a shared (read) lock at BOTH levels."""
        start_time = time.time()
        
        # Tier 1: Global Level Check
        with self.shared_lock(self.GLOBAL_KEY, timeout=timeout) as g_acquired:
            if not g_acquired:
                yield False
                return
            
            # Tier 2: Local Key Level Check (Calculate remaining timeout balance)
            rem_timeout = None if timeout is None else max(0.0, timeout - (time.time() - start_time))
            with self.shared_lock(key, timeout=rem_timeout) as k_acquired:
                yield k_acquired

    @contextmanager
    def write_lock(self, key, timeout=None):
        """Local writers identify as exclusive at the global level, exclusive at key level."""
        start_time = time.time()
        
        # Tier 1: Global Level Check (Exclusive to block checkpoints and other writes)
        with self.exclusive_lock(self.GLOBAL_KEY, timeout=timeout) as g_acquired:
            if not g_acquired:
                yield False
                return
            
            # Tier 2: Local Key Level Check (Calculate remaining timeout balance)
            rem_timeout = None if timeout is None else max(0.0, timeout - (time.time() - start_time))
            with self.exclusive_lock(key, timeout=rem_timeout) as k_acquired:
                yield k_acquired
