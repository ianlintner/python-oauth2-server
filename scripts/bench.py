"""Closed-loop async benchmark fallback for when `oha`/`wrk` aren't installed.

Usage:
    uv run python scripts/bench.py <url> [--method POST] [--body-file f] \
        [--header "K: V"] [--concurrency 64] [--duration 15]

Prints throughput (req/s) and p50/p95 latency (ms) for one endpoint, matching
the shape of `oha`'s summary so `scripts/bench.sh` can record either output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time

import httpx


async def _worker(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    body: bytes | None,
    headers: dict[str, str],
    stop_at: float,
    latencies: list[float],
    errors: list[int],
) -> None:
    while time.monotonic() < stop_at:
        start = time.perf_counter()
        try:
            resp = await client.request(method, url, content=body, headers=headers)
            latencies.append((time.perf_counter() - start) * 1000)
            if resp.status_code >= 400:
                errors.append(resp.status_code)
        except Exception:  # noqa: BLE001 - count as error, keep benchmarking
            latencies.append((time.perf_counter() - start) * 1000)
            errors.append(-1)


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(int(len(sorted_values) * pct), len(sorted_values) - 1)
    return sorted_values[idx]


async def run(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    concurrency: int,
    duration: float,
) -> None:
    latencies: list[float] = []
    errors: list[int] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        stop_at = time.monotonic() + duration
        start = time.monotonic()
        await asyncio.gather(
            *(
                _worker(client, method, url, body, headers, stop_at, latencies, errors)
                for _ in range(concurrency)
            )
        )
        elapsed = time.monotonic() - start

    latencies.sort()
    total = len(latencies)
    print(f"URL: {method} {url}")
    print(f"Concurrency: {concurrency}, Duration: {elapsed:.2f}s")
    print(f"Requests: {total}, Errors: {len(errors)}")
    print(f"Req/s: {total / elapsed:.2f}")
    print(f"Latency p50: {_percentile(latencies, 0.50):.2f} ms")
    print(f"Latency p95: {_percentile(latencies, 0.95):.2f} ms")
    print(f"Latency p99: {_percentile(latencies, 0.99):.2f} ms")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body-file", default=None, help="Path to a file with the request body")
    parser.add_argument("--json-body", default=None, help="Inline JSON body")
    parser.add_argument("--header", action="append", default=[], help="'Key: Value', repeatable")
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--duration", type=float, default=15.0)
    args = parser.parse_args()

    body: bytes | None = None
    if args.body_file:
        body = open(args.body_file, "rb").read()  # noqa: SIM115
    elif args.json_body:
        body = json.dumps(json.loads(args.json_body)).encode()

    headers: dict[str, str] = {}
    for h in args.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    asyncio.run(run(args.url, args.method, body, headers, args.concurrency, args.duration))


if __name__ == "__main__":
    main()
