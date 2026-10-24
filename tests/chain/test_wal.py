from eth_utils import keccak

from sihchain.wal import WriteAheadLog


def fill(wal, n):
    return [wal.append(f"a{i}", keccak(f"alert{i}".encode()), keccak(f"bundle{i}".encode())) for i in range(n)]


def test_append_links_and_is_idempotent():
    wal = WriteAheadLog()
    es = fill(wal, 5)
    assert [e.seq for e in es] == [0, 1, 2, 3, 4]
    assert es[1].prev_hash == es[0].entry_hash
    again = wal.append("a2", keccak(b"different"), keccak(b"different"))
    assert again.entry_hash == es[2].entry_hash and wal.count() == 5
    assert wal.verify_chain() == (True, "ok")


def test_edit_detected():
    wal = WriteAheadLog()
    fill(wal, 5)
    wal._db.execute("UPDATE entries SET alert_hash=? WHERE seq=2", (keccak(b"forged"),))
    ok, msg = wal.verify_chain()
    assert not ok and "seq 2" in msg


def test_middle_deletion_detected():
    wal = WriteAheadLog()
    fill(wal, 5)
    wal._db.execute("DELETE FROM entries WHERE seq=2")
    ok, msg = wal.verify_chain()
    assert not ok and "gap" in msg


def test_reorder_detected():
    wal = WriteAheadLog()
    fill(wal, 4)
    wal._db.execute("UPDATE entries SET seq=99 WHERE seq=1")
    wal._db.execute("UPDATE entries SET seq=1 WHERE seq=2")
    wal._db.execute("UPDATE entries SET seq=2 WHERE seq=99")
    assert not wal.verify_chain()[0]


def test_persistence(tmp_path):
    path = str(tmp_path / "wal.sqlite")
    w1 = WriteAheadLog(path)
    fill(w1, 3)
    w2 = WriteAheadLog(path)
    e = w2.append("a3", keccak(b"x"), keccak(b"y"))
    assert e.seq == 3 and w2.verify_chain()[0]
