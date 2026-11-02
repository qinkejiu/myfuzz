"""Append-only hash-chain decisions. Integrity is not native provenance."""
from hashlib import sha256
import json
from pathlib import Path

from .model import canonical

ZERO = "0" * 64


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Never overwrite or silently resume a preexisting decision stream.
        with self.path.open("x"):
            pass
        self.head, self.count = ZERO, 0

    def append(self, document):
        row = {"sequence": self.count, "previous": self.head, "document": document}
        digest = sha256(canonical(row)).hexdigest()
        line = canonical({**row, "sha256": digest}).decode() + "\n"
        with self.path.open("a") as stream:
            stream.write(line)
            stream.flush()
        self.head, self.count = digest, self.count + 1
        return digest


def verify_journal(path, *, expected_head=None):
    previous, count = ZERO, 0
    with Path(path).open() as stream:
        for line in stream:
            row = json.loads(line)
            if type(row) is not dict or set(row) != {"sequence", "previous", "document", "sha256"}:
                raise ValueError("invalid journal row")
            digest = row.pop("sha256")
            if (type(row["sequence"]) is not int or row["sequence"] != count
                    or row["previous"] != previous or sha256(canonical(row)).hexdigest() != digest):
                raise ValueError("journal integrity mismatch")
            previous, count = digest, count + 1
    if expected_head is not None and previous != expected_head:
        raise ValueError("journal terminal head mismatch")
    return {"records": count, "head": previous, "native_authority": False}
