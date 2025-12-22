#!/usr/bin/env python3
"""Multi-threaded Python test fixture."""

import threading
import time


def worker(thread_id, iterations):
    """Worker function called from multiple threads."""
    total = 0
    for i in range(iterations):
        total += compute(i)
        time.sleep(0.001)  # Small delay to interleave threads
    print(f"Thread {thread_id}: total={total}")
    return total


def compute(n):
    """Simple computation called by worker."""
    return n * n


def main():
    """Run multi-threaded test."""
    num_threads = 4
    iterations = 10

    print(f"Starting {num_threads} threads")

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i, iterations))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("All threads completed")


if __name__ == "__main__":
    main()
