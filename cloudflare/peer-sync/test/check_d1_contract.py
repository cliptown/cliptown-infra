#!/usr/bin/env python3
"""Validate Cloudflare D1 desired SQL against local SQLite without credentials."""
import pathlib
import sqlite3

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = (ROOT / "migrations/0001_encrypted_text_cache.sql").read_text()
PRUNE = (ROOT / "queries/prune_account.sql").read_text()


def put(db, account, item, seq, size=1):
    payload = bytes([seq % 256]) * size
    db.execute(
        """INSERT INTO encrypted_text_envelopes
           (account_id,envelope_id,server_sequence,ciphertext,ciphertext_digest,
            ciphertext_bytes,stored_bytes,received_ms,device_id)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (account, item, seq, payload, "a" * 64, size, size + 512, 1700000000000 + seq, "device_a"),
    )


def keep(db, account):
    return {row[0] for row in db.execute(
        "SELECT envelope_id FROM encrypted_text_envelopes WHERE account_id=?", (account,)
    )}


def test():
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA)
    for i in range(2001):
        put(db, "owner_a", "clip_" + str(i), i + 1)
    put(db, "owner_b", "unrelated", 1)
    db.execute(PRUNE, ("owner_a", "owner_a"))
    assert len(keep(db, "owner_a")) == 2000
    assert "clip_0" not in keep(db, "owner_a")
    assert keep(db, "owner_b") == {"unrelated"}

    # Byte quota excludes older entries, without touching another account.
    db.execute("DELETE FROM encrypted_text_envelopes WHERE account_id = ?", ("owner_a",))
    put(db, "owner_a", "older", 1)
    put(db, "owner_a", "large", 2, 5 * 1024 * 1024 - 512)
    db.execute(PRUNE, ("owner_a", "owner_a"))
    assert keep(db, "owner_a") == {"large"}
    assert keep(db, "owner_b") == {"unrelated"}

    # D1 schema itself must reject out-of-quota and falsely charged inserts.
    try:
        put(db, "owner_a", "oversize", 10, 5 * 1024 * 1024)
        raise AssertionError("oversized ciphertext admitted")
    except sqlite3.IntegrityError:
        pass
    try:
        db.execute("UPDATE encrypted_text_envelopes SET stored_bytes = 1 WHERE account_id=?", ("owner_a",))
        raise AssertionError("untrusted stored_bytes admitted")
    except sqlite3.IntegrityError:
        pass
    print("PASS: SQLite schema/retention/account isolation/quota checks")


if __name__ == "__main__":
    test()
