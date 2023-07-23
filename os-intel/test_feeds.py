import json
import logging
import pathlib

import pytest
from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink,TypeDBSource
from stixorm.module.typedb_lib.instructions import ResultStatus

from stixorm.module.definitions.os_threat.classes import ThreatReference,ThreatSubObject,Feed,Feeds
from stix2.v21.common import ExternalReference,MarkingDefinition,StatementMarking
from stix2.v21 import Identity,ObservedData,Indicator,IPv4Address,File,Bundle

from helpers import get_storage

import logging

#from stixorm.module.typedb_lib.import_type_factory import AttackDomains, AttackVersions

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')

class FeedsManager(object):

    def __init__(self,db_connection= {"uri": "localhost","port": "1729","database": "stix","user": None,"password": None},cache_connection="postgresql://admin:admin@localhost:5432/stixorm"):
        schema_path = str(pathlib.Path(__file__).parents[1])
        import_type = import_type_factory.get_all_imports()

        self._typedb_sink = TypeDBSink(db_connection, True, import_type)
        self._typedb_source = TypeDBSource(db_connection, import_type)

        self._cache_db = get_storage(cache_connection, "test_feeds")
        self._cache_db.delete()

    def add_feeds(self,feeds):
        if type(feeds)==list:
            results = self._typedb_sink.add(feeds)

            for result in results:
                origin_feed = list(filter(lambda f: f.id == result.id,feeds))
                if len(origin_feed) == 1:
                    self._cache_db.write_objects(origin_feed)

                else: continue
            return results
        else:
            raise Exception("requires list of feeds and feed objects")
    def get_feeds(self):
        retdict = self._cache_db.read_records("feeds")
        return retdict

@pytest.fixture
def empty_feed_list():

    feeds = []
    for feedno in range(10):
        one_feed = Feed(name=f'feed_{feedno}')
        feeds.append(one_feed)

    # create the Feeds object
    root_feed = Feeds(name='root_feed',
                  contained=feeds)
    feeds.append(root_feed)
    return feeds

def test_empty_feeds(empty_feed_list):

    fm = FeedsManager()
    logging.debug('List of empty feeds')

    results = fm.add_feeds(empty_feed_list)

    assert all(result.status == ResultStatus.SUCCESS for result in results)==True

    retrieved = fm.get_feeds()

    assert len(retrieved) == len(empty_feed_list)
