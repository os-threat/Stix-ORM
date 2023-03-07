import json
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.authorise import import_type_factory
from stix.module.parsing.parse_objects import parse
import logging
logger = logging.getLogger(__name__)

import_type = import_type_factory.get_attack_import()
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}


def test_initialise():
    typedb = TypeDBSink(connection, True, import_type)


def load_file(fullname):
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb = TypeDBSink(connection, True, import_type)
        typedb.add(json_text)


def check_in_out(fullname, stixid):
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb = TypeDBSink(connection, True, import_type)
        typedb.add(json_text)

        #  print original object
        obj_list = json_text.get('objects', False)
        for obj in obj_list:
            if obj.get('id', False) == stixid:
                stix_obj = parse(obj)
                print(' ---------------------------Original Object----------------------')
                print(stix_obj.serialize(pretty=True))

        # retrieve object from TypeDB
        typedb = TypeDBSource(connection, import_type)
        stix_dict = typedb.get(stixid)
        stix_obj = parse(stix_dict)
        print('\n ---------------------------Query Object----------------------')
        print(stix_obj.serialize(pretty=True))


# if this file is run directly, then start here
if __name__ == '__main__':

    ex_path = "data/examples/"
    file1 = "granular_markings.json"  # specific object
    stixid = "indicator--1ed8caa7-a708-4706-b651-f1186ede6ca1"

    file2 = "attack_pattern_malware.json"  # list of objects

    std_path = "data/standard/"
    file3 = 'file_basic.json'  # hashes example
    file4 = 'file_binary.json' # extensions, sub-object

    report_data = "data/threat_reports/"
    file5 = "apt1.json"

    #test_initialise()
    #load_file(report_data + file5)
    #check_in_out(ex_path + file1, stixid)
