#!/usr/bin/env python3
"""Execute exact Worker SQL against real SQLite transactions without secrets.

This is SQLite/D1 SQL conformance, NOT a live Cloudflare D1 provider test.
D1's Worker binding batch performs the corresponding atomic transaction.
"""
import hashlib
import json
import pathlib
import sqlite3
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONNECTION_ROOT = ROOT.parents[1]
SOURCE = """import * as q from './cloudflare/peer-sync/src/cache_sql.mjs';
process.stdout.write(JSON.stringify(q));"""
output = subprocess.run(
    ["node", "--input-type=module", "-e", SOURCE],
    cwd=CONNECTION_ROOT,
    check=True,
    capture_output=True,
    text=True,
)
SQL = json.loads(output.stdout)
ONE_MIB = 1024 * 1024


def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    for filename in (
        "0001_encrypted_text_cache.sql", "0002_account_sequences.sql"
    ):
        db.executescript((ROOT / "migrations" / filename).read_text())
    return db


def append(db, account, name, ciphertext=b"\x01", device="device_a"):
    digest = hashlib.sha256(ciphertext).hexdigest()
    with db:
        db.execute(SQL["ALLOCATE_SEQUENCE_SQL"], (account,))
        db.execute(
            SQL["APPEND_TEXT_SQL"],
            (account, name, ciphertext, digest, len(ciphertext),
             len(ciphertext) + 512, 1700000000000, device, account),
        )
        db.execute(SQL["PRUNE_ACCOUNT_SQL"], (account, account))
        receipt = db.execute(SQL["LOOKUP_RECEIPT_SQL"], (account, name)).fetchone()
        assert receipt is not None
        return receipt["server_sequence"]


def records(db, account):
    return [row["envelope_id"] for row in db.execute(
        "SELECT envelope_id FROM encrypted_text_envelopes WHERE account_id=? "
        "ORDER BY server_sequence DESC", (account,),
    )]


def test_account_and_item_limits():
    db = database()
    assert append(db, "alpha", "entry_0") == 1
    assert append(db, "beta", "entry_0") == 1
    for n in range(1, 2001):
        assert append(db, "alpha", "entry_" + str(n)) == n + 1
    assert len(records(db, "alpha")) == 2000
    assert "entry_0" not in records(db, "alpha")
    assert records(db, "beta") == ["entry_0"]
    assert db.execute(
        "SELECT last_sequence FROM cloud_cache_account_sequences WHERE account_id='alpha'"
    ).fetchone()[0] == 2001

    page = db.execute(SQL["READ_CACHE_PAGE_SQL"], ("alpha", None, None, 3)).fetchall()
    assert [r["envelope_id"] for r in page] == [
        "entry_2000", "entry_1999", "entry_1998"
    ]
    after = db.execute(SQL["READ_CACHE_PAGE_SQL"], ("alpha", 1999, 1999, 3))
    assert after.fetchone()["server_sequence"] == 1998
    db.close()


def test_byte_quota_and_atomic_conflict():
    db = database()
    assert append(db, "alpha", "old") == 1
    assert append(db, "alpha", "new", b"\x17" * (5 * ONE_MIB - 512)) == 2
    assert records(db, "alpha") == ["new"]
    assert db.execute(
        "SELECT SUM(stored_bytes) FROM encrypted_text_envelopes WHERE account_id='alpha'"
    ).fetchone()[0] == 5 * ONE_MIB

    before = db.execute(
        "SELECT last_sequence FROM cloud_cache_account_sequences WHERE account_id='alpha'"
    ).fetchone()[0]
    try:
        append(db, "alpha", "new", b"different")
        raise AssertionError("duplicate ID accepted")
    except sqlite3.IntegrityError:
        pass
    assert records(db, "alpha") == ["new"]
    assert db.execute(
        "SELECT last_sequence FROM cloud_cache_account_sequences WHERE account_id='alpha'"
    ).fetchone()[0] == before

    try:
        append(db, "alpha", "oversized", b"\x18" * (5 * ONE_MIB))
        raise AssertionError("oversized item accepted")
    except sqlite3.IntegrityError:
        pass
    assert records(db, "alpha") == ["new"]
    db.close()


def test_prune_failure_rolls_back_sequence_and_insert():
    db = database()
    for n in range(2000):
        append(db, "alpha", "clip_" + str(n))
    db.executescript(
        "CREATE TRIGGER deny_eviction BEFORE DELETE ON encrypted_text_envelopes "
        "BEGIN SELECT RAISE(ABORT, 'injected prune failure'); END;"
    )
    try:
        append(db, "alpha", "clip_extra")
        raise AssertionError("injected prune failure was accepted")
    except sqlite3.IntegrityError:
        pass
    assert len(records(db, "alpha")) == 2000
    assert "clip_extra" not in records(db, "alpha")
    assert db.execute(
        "SELECT last_sequence FROM cloud_cache_account_sequences WHERE account_id='alpha'"
    ).fetchone()[0] == 2000
    db.close()


def test_no_account_cross_talk_and_prune_file_parity():
    db = database()
    injected_account = "alpha' OR 1=1 --"
    assert append(db, injected_account, "item_1") == 1
    assert append(db, "beta", "item_1") == 1
    assert append(db, injected_account, "item_2", b"\x03" * (5 * ONE_MIB - 512)) == 2
    assert records(db, injected_account) == ["item_2"]
    assert records(db, "beta") == ["item_1"]

    file_sql = (ROOT / "queries" / "prune_account.sql").read_text()
    db.execute(file_sql, ("beta", "beta"))
    assert records(db, "beta") == ["item_1"]
    db.close()


if __name__ == "__main__":
    test_account_and_item_limits()
    test_byte_quota_and_atomic_conflict()
    test_prune_failure_rolls_back_sequence_and_insert()
    test_no_account_cross_talk_and_prune_file_parity()
    print("PASS: exact D1 SQL in SQLite; quota, sequence, rollback, paging, isolation")
