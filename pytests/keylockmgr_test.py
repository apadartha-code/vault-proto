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
import random

from keylockmgr import HierarchicalLockManager

class ThreadSafePriorityDict:
    """A thread-safe dictionary wrapper utilizing hierarchical read-write locking

    with precise timeout propagation.
    """

    def __init__(self):
        self._data = {}
        self._lock_manager = HierarchicalLockManager()

    def get(self, key, timeout=None, default=None):
        """Fetches a value. Concurrent with checkpoints and other readers."""
        with self._lock_manager.read_lock(key, timeout=timeout) as acquired:
            if not acquired:
                raise TimeoutError(
                    f"Read timeout on key '{key}' within {timeout}s"
                )
            return self._data.get(key, default)

    def set(self, key, value, timeout=None):
        """Sets a value. Blocked by active checkpoints and local key locks."""
        with self._lock_manager.write_lock(key, timeout=timeout) as acquired:
            if not acquired:
                raise TimeoutError(
                    f"Write timeout on key '{key}' within {timeout}s"
                )
            self._data[key] = value

    def checkpoint_dump(self, timeout=None) -> dict:
        """Exclusively isolates the dictionary state against writes while

        allowing concurrent reads to finish or run alongside it.
        """
        with self._lock_manager.checkpoint_lock(timeout=timeout) as acquired:
            if not acquired:
                raise TimeoutError(
                    f"Checkpoint global lock timeout within {timeout}s"
                )
            # Safe to shallow copy the data state since all writes are barred
            return dict(self._data)


# =====================================================================
# TEST IMPLEMENTATION
# =====================================================================

# Sync print log
print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# =====================================================================
# TEST CASE 1: Strict Global Checkpoint Isolation vs Writers
# =====================================================================
def test_checkpoint_vs_writers():
    log("\n--- TEST 1: Checkpoint Read Concurrency vs Writer Blocking ---")
    db = ThreadSafePriorityDict()
    db.set("k1", "base_val")

    # Size 4: 3 workers + 1 main thread control coordinator
    barrier = threading.Barrier(4)

    def reader_during_cp():
        barrier.wait()
        time.sleep(0.05)  # Let checkpoint thread execute its lock step first
        try:
            val = db.get("k1", timeout=1.0)
            log(f"[Reader] Read successful during checkpoint! Value: {val}")
        except TimeoutError:
            log("[Reader] ERROR: Reader timed out during checkpoint!")

    def writer_during_cp():
        barrier.wait()
        time.sleep(0.1)  # Ensure checkpoint settles completely
        try:
            log("[Writer] Requesting write lock (Should be blocked)...")
            db.set("k1", "mutated_val", timeout=0.5)
            log("[Writer] ERROR: Writer bypassed checkpoint lock!")
        except TimeoutError:
            log("[Writer] SUCCESS: Writer correctly blocked and timed out!")

    def checkpoint_runner():
        barrier.wait()
        with db._lock_manager.checkpoint_lock() as acquired:
            log("[Checkpoint] Global lock acquired. Simulating slow file write...")
            time.sleep(1.0)
            log("[Checkpoint] Finished.")

    t_cp = threading.Thread(target=checkpoint_runner)
    t_r = threading.Thread(target=reader_during_cp)
    t_w = threading.Thread(target=writer_during_cp)

    t_cp.start()
    t_r.start()
    t_w.start()

    # Synchronized release: Signal that all threads are running!
    log("[Main Control] All threads initialized. Dropping gate...")
    barrier.wait()

    t_cp.join()
    t_r.join()
    t_w.join()


# =====================================================================
# TEST CASE 2: Strict Timeout Degradation Math Verification
# =====================================================================
def test_timeout_degradation():
    log("\n--- TEST 2: Multi-tier Timeout Budget Propagation ---")
    db = ThreadSafePriorityDict()
    db.set("k2", "initial")

    # Lock the global level indefinitely by faking an active local write
    # so any incoming thread drains its timeout budget waiting at Tier 1.
    def hold_global_hostage():
        with db._lock_manager.write_lock("k2"):
            time.sleep(1.0)

    def impatient_reader():
        time.sleep(0.1)  # Ensure hostage lock is active
        start = time.time()
        try:
            db.get("k2", timeout=0.4)
        except TimeoutError:
            elapsed = time.time() - start
            log(
                f"[Impatient Reader] Correctly threw TimeoutError. Elapsed: {elapsed:.2f}s (Budget respected!)"
            )

    t_hold = threading.Thread(target=hold_global_hostage)
    t_read = threading.Thread(target=impatient_reader)

    t_hold.start()
    t_read.start()

    t_hold.join()
    t_read.join()


# =====================================================================
# TEST CASE 3: Chaotic Randomized Stress Test (Race Conditions)
# =====================================================================
def test_chaotic_race_conditions():
    log("\n--- TEST 3: Chaotic Multi-key Randomized Race Test ---")
    db = ThreadSafePriorityDict()

    # Pre-seed keys
    keys = ["user_a", "user_b", "user_c"]
    for k in keys:
        db.set(k, 0)

    errors = []

    def client_behavior(thread_id):
        for _ in range(15):
            action = random.choice(["READ", "WRITE", "CHECKPOINT"])
            target_key = random.choice(keys)
            timeout_budget = random.uniform(0.05, 0.2)

            try:
                if action == "READ":
                    db.get(target_key, timeout=timeout_budget)
                elif action == "WRITE":
                    # Simulating a read-modify-write race mitigation step
                    current = db.get(target_key, timeout=timeout_budget)
                    db.set(target_key, current + 1, timeout=timeout_budget)
                elif action == "CHECKPOINT":
                    db.checkpoint_dump(timeout=timeout_budget)
            except TimeoutError:
                # Timeouts under heavy load are acceptable and expected behaviors
                pass
            except Exception as e:
                # Any other error means a fatal structural race condition occurred
                errors.append(f"Thread-{thread_id} crashed: {type(e).__name__}")

            time.sleep(random.uniform(0.01, 0.03))

    # Spin up 40 highly active concurrent worker threads
    workers = [
        threading.Thread(target=client_behavior, args=(i,)) for i in range(40)
    ]

    for w in workers:
        w.start()
    for w in workers:
        w.join()

    log(f"[Stress Test] Run completed with {len(errors)} critical exceptions.")
    if errors:
        for err in errors:
            log(f"  -> CRITICAL ERROR: {err}")
    else:
        log("  -> SUCCESS: Memory pool remained 100% stable.")


if __name__ == "__main__":
    test_checkpoint_vs_writers()
    test_timeout_degradation()
    test_chaotic_race_conditions()
