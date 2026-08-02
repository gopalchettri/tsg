"""dal.guid() must be SEQUENTIAL under SQL Server's uniqueidentifier collation.

Nine tables have a uniqueidentifier PRIMARY KEY, which SQL Server makes CLUSTERED by default —
so the key's sort order is the physical row order, and a random key means a page split per
insert forever. The subtlety these tests exist to pin: SQL Server does NOT sort GUIDs by byte
order. It compares the LAST 6 bytes first, then 8-9, 6-7, 4-5, and 0-3 last. A UUIDv7 (timestamp
in the FIRST bytes) is therefore sequential on PostgreSQL and useless here — a regression to
uuid4 OR to UUIDv7 must both fail.
"""
from __future__ import annotations

import uuid

from app.db.dal import guid

#: SQL Server's uniqueidentifier comparison order, most significant group first.
_MSSQL_ORDER = (10, 11, 12, 13, 14, 15, 8, 9, 6, 7, 4, 5, 0, 1, 2, 3)


def _mssql_sort_key(g: str) -> bytes:
    """The byte sequence SQL Server actually orders a uniqueidentifier by."""
    raw = uuid.UUID(g).bytes
    return bytes(raw[i] for i in _MSSQL_ORDER)


def test_guids_ascend_in_sql_server_collation_order():
    """The whole point: successive ids must land at the END of the clustered index, not the middle.

    The property is on the LEADING 6 bytes of SQL Server's sort key — the timestamp. Ids minted
    inside the same millisecond share that prefix and then tie-break on random bytes; that is
    deliberate and harmless, because they still cluster onto the same page region. What must
    NEVER happen is the prefix going BACKWARDS, which is what drives an insert into the middle of
    the table. uuid4 fails this outright; UUIDv7 fails it too, because its timestamp sits in the
    bytes SQL Server compares LAST.
    """
    import time
    prefixes = []
    for _ in range(40):
        prefixes.append(_mssql_sort_key(guid())[:6])
        time.sleep(0.002)                      # cross millisecond boundaries
    assert prefixes == sorted(prefixes), "guid() is not sequential in SQL Server's ordering"
    assert len(set(prefixes)) > 1, "clock never advanced — the test proved nothing"


def test_a_uuid4_baseline_would_fail_the_ordering_property():
    """Guards the guard: proves the assertion above can actually fail, so it is not vacuous."""
    import uuid as _uuid
    prefixes = [_mssql_sort_key(str(_uuid.uuid4()))[:6] for _ in range(200)]
    assert prefixes != sorted(prefixes)


def test_timestamp_lives_in_the_last_six_bytes():
    """Pins the layout, so a well-meaning switch to uuid7() fails loudly instead of silently
    reintroducing the fragmentation this replaced."""
    import time
    before = int(time.time() * 1000)
    raw = uuid.UUID(guid()).bytes
    after = int(time.time() * 1000)
    embedded = int.from_bytes(raw[10:], "big")
    assert before - 1000 <= embedded <= after + 1000


def test_still_a_well_formed_uuid_that_round_trips():
    """The GUID TypeDecorator revalidates via uuid.UUID(), and _valid_guid gates API input."""
    from app.db.dal import _valid_guid

    for _ in range(50):
        g = guid()
        assert str(uuid.UUID(g)) == g
        assert _valid_guid(g)
        assert uuid.UUID(g).version == 8          # custom layout, RFC 9562
        assert uuid.UUID(g).variant == uuid.RFC_4122


def test_ids_are_unique_under_burst_generation():
    """~74 bits of randomness survive per millisecond; a burst inside one tick must not collide."""
    ids = [guid() for _ in range(20_000)]
    assert len(set(ids)) == len(ids)
