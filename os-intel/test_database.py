import pytest
import sqlstorage
import pgstorage
from stixorm.module.definitions.os_threat import Feed, Feeds, ThreatSubObject

from helpers import tmp_storage

def test_reset_db(tmpdir="./localdb"):

    store = tmp_storage(tmpdir)

    tables = store.tables()

    for table in tables:
        print('Table name = %s' % table)

def test_insert_db(tmpdir="./localdb"):
    print('\nInserting test\n')
    store = tmp_storage(tmpdir)

    # create the Feeds object
    feeds_a = Feeds(name='parent',
                  description="a",
                  paid=False,
                  free=True,
                  labels=[],
                  lang="en",
                  external_references=[],
                  object_marking_refs = [],
                  contained=[])

    feed_a = Feed(name='child')

    store.write_objects([feeds_a,feed_a])

    tables = store.tables()

    for table in tables:
        print('Table name = %s' % table)

    print('\nRetrieving feeds\n')
    rets = store.read_records("feeds")

    assert len(rets)==1

    assert rets[0]['id'] == feeds_a.id

    rets = store.read_records("feed")

    assert len(rets)==1

    assert rets[0]['id'] == feed_a.id
