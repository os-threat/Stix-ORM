import json
import os
import datetime
import stix2
from stix2 import Identity

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

from stixorm.module.authorise import import_type_factory
from stixorm.module.typedb import TypeDBSink,TypeDBSource
from stixorm.module.typedb_lib.instructions import ResultStatus
import stix2

import_type = import_type_factory.get_default_import()

connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stixorm",
    "user": None,
    "password": None
}
def load_sample():
    with open('./data/os-threat/incident/human_trigger.json','r') as file:
        bundle_json = json.load(file)

        typedb = TypeDBSink(connection=connection,
                            clear=True,
                            import_type=import_type)

        results = typedb.add(bundle_json)

        for result in results:
            print(result)


load_sample()