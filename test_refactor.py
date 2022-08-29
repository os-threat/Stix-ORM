import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.import_stix_to_typeql import stix2_to_typeql
from typedb.client import *


import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

from stix2 import (v21, parse)

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix2",
    "user": None,
    "password": None
}


test_id = "indicator--1ed8caa7-a708-4706-b651-f1186ede6ca1"


def load_file(path):
    with open(path, mode="r", encoding="utf-8") as f:
        json_text =  json.load(f)
        typedb = TypeDBSink(connection, True, "STIX21")
        typedb.add(json_text)


def query_id(stixid):
    typedb = TypeDBSource(connection, "STIX21")
    stix_dict = typedb.get(stixid)
    stix_obj = parse(stix_dict)    
    print(stix_obj.serialize(pretty=True))


def test_slashes(path):
    orig = ''
    ret = ''
    with open(path, mode="r", encoding="utf-8") as f:
        json_text =  json.load(f)
        typedb = TypeDBSink(connection, True, "STIX21")
        typedb.add(json_text)
        for stix_obj in json_text.get("objects", []):
            if stix_obj.get("type") == "indicator":
                orig = parse(stix_obj)
    typedb = TypeDBSource(connection, "STIX21")
    stix_dict = typedb.get(test_id)
    ret = parse(stix_dict)
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
    print(orig.serialize(pretty=True))
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
    print(ret.serialize(pretty=True))
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
    opat = orig["pattern"]
    rpat = ret["pattern"]
    if opat == rpat:
        print("equals")
        print(f'original -> {opat}')
        print(f'retruned -> {rpat}')
    else:
        print("not equals")
        print(f'original -> {opat}')
        print(f'retruned -> {rpat}')


def check_dir(path):
    dirFiles = os.listdir(path)
    sorted_files = sorted(dirFiles)
    typedb_sink = TypeDBSink(connection, True, "STIX21")
    typedb_source = TypeDBSource(connection, "STIX21")
    for s_file in sorted_files:
        print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        print(f'==================== {s_file} ===================================')
        print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        with open(os.path.join(path, s_file), mode="r", encoding="utf-8") as f:
            json_text = json.load(f)
            stix_objs = json_text["objects"]
            for stix_dict in stix_objs:
                stix_id = stix_dict.get('id')
                stix_type = stix_dict.get('type')
                stix_obj = parse(stix_dict)
                typedb_sink.add(stix_obj)
                stix_out = typedb_source.get(stix_id)
                print(f'-------------- object => {stix_type} ------------------------------')
                # print(stix_obj.serialize(pretty=True))
                # print("=====")
                # print(stix_out.serialize(pretty=True))
                print(f' In=> created: {stix_obj.get("created")}, modified {stix_obj.get("modified")}')
                print(f'Out=> created: {stix_out.get("created")}, modified {stix_out.get("modified")}')
                print(f'-------------- object => {stix_type} ------------------------------')


# if this file is run directly, then start here
if __name__ == '__main__':
    
    data_path = "data/examples/"
    file = "granular_markings.json"
    
    #load_file(data_path+file)
    #query_id(test_id)
    #check_dir(data_path)
    test_slashes(data_path+file)
    