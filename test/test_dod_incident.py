import json
import os
import datetime
import stix2
from stix2 import Identity
import pytest
import pytest
from stix2 import parse
from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink
from stixorm.module.typedb_lib.instructions import ResultStatus

import_type = import_type_factory.get_all_imports()

def quick_check():
    with open('./data/os-threat/incident/human_trigger.json','r') as file:
        bundle_json = json.load(file)

        missing = []
        print('Missing %d' % len(missing))

        found = 0
        for object in bundle_json['objects']:
            is_m = any([object['id']==m for m in missing])
            if is_m:
                print("Source object : %s" % object['id'])
                spec = [m for m in missing if object['id'] == m]
                print("\tMissing object : %s" % spec)
                found += 1
            if 'created_by_ref' in object:
                is_m = any([object['created_by_ref'] == m for m in missing])
                if is_m:
                    print("Source object : %s" % object['id'])
                    spec = [m for m in missing if object['created_by_ref'] == m]
                    print("\tMissing object : %s" % spec)
                    found += 1
            if 'sighting_refs' in object:
                for ref in object['sighting_refs']:
                    is_m = any([ref == m for m in missing])
                    if is_m:
                        print("Source object : %s" % object['id'])
                        found += 1
            if object['type']=='sighting':
                print(object)
        print('Total found %d' % found)

@pytest.fixture
def database(generate_connection):
    db = TypeDBSink(
        connection=generate_connection,
        clear=True,
        import_type=import_type,
        strict_failure=True,
    )
    db.clear_db()
    db = TypeDBSink(
        connection=generate_connection,
        clear=True,
        import_type=import_type,
        strict_failure=True
    )
    yield db
    db.clear_db()
    db.clear_db()

class TestDOD:

    def setUp(self, generate_connection):
        self.clean_db(generate_connection)

    def tearDown(self, generate_connection):
        self.clean_db(generate_connection)
    def test_load(self,database:TypeDBSink):
        import pathlib
        import pytest
        path = pathlib.Path(__file__).parents[0].joinpath('data/os-threat/incident/human_trigger.json')
        if not path.is_file():
            pytest.skip(f"Missing test data: {path}")
        with open(str(path),'r') as file:

            bundle_json = json.load(file)

            inserts = database.add(bundle_json)

            for result in inserts:
                assert result.message is None
                assert result.error is None
