#!/usr/bin/env python3
"""Generate RFC 6962 Merkle test vectors with an independent implementation.

This exists so the JavaScript tree is checked against something other than
itself. Written straight from RFC 6962 section 2.1 with hashlib only.

    python scripts/gen_vectors.py > spec/vectors/merkle.json
"""

import hashlib
import json


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    if len(leaves) == 0:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def path(m, leaves):
    if len(leaves) <= 1:
        return []
    k = split(len(leaves))
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


def subproof(m, leaves, b):
    if m == len(leaves):
        return [] if b else [mth(leaves)]
    k = split(len(leaves))
    if m <= k:
        return subproof(m, leaves[:k], b) + [mth(leaves[k:])]
    return subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def consistency(first, leaves):
    if first == len(leaves):
        return []
    return subproof(first, leaves, True)


def hx(b: bytes) -> str:
    return b.hex()


def main():
    data = [f"provenant-event-{i}".encode() for i in range(9)]
    leaves = [leaf_hash(d) for d in data]

    vectors = {
        "source": "scripts/gen_vectors.py (independent Python implementation of RFC 6962)",
        "hash": "sha256",
        "leafPrefix": "00",
        "nodePrefix": "01",
        "entries": [{"data": d.decode(), "leaf": hx(leaf_hash(d))} for d in data],
        "roots": [{"size": n, "root": hx(mth(leaves[:n]))} for n in range(len(leaves) + 1)],
        "inclusion": [],
        "consistency": [],
    }

    for size in (1, 2, 3, 4, 5, 7, 8, 9):
        for index in range(size):
            vectors["inclusion"].append(
                {
                    "size": size,
                    "index": index,
                    "leaf": hx(leaves[index]),
                    "root": hx(mth(leaves[:size])),
                    "path": [hx(h) for h in path(index, leaves[:size])],
                }
            )

    for first, second in ((1, 2), (1, 7), (3, 7), (4, 8), (6, 9), (7, 7), (2, 9)):
        vectors["consistency"].append(
            {
                "first": first,
                "second": second,
                "firstRoot": hx(mth(leaves[:first])),
                "secondRoot": hx(mth(leaves[:second])),
                "proof": [hx(h) for h in consistency(first, leaves[:second])],
            }
        )

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
