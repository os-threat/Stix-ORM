import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.stql import stix2_to_typeql
from typedb.client import *


from loguru import logger

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

@logger.catch
def load_file(path):
    with open(path, mode="r", encoding="utf-8") as f:
        json_text =  json.load(f)
        typedb = TypeDBSink(connection, True, "Stix21")
        typedb.add(json_text)

@logger.catch
def query_id(stixid):
    typedb = TypeDBSource(connection, "Stix21")
    stix_dict = typedb.get(stixid)
    stix_obj = parse(stix_dict)    
    print(stix_obj.serialize(pretty=True))
    

# if this file is run directly, then start here
if __name__ == '__main__':
    
    data_path = "data/examples/"
    file = "granular_markings.json"
    
    load_file(data_path+file)
    query_id(test_id)
    #direct(data_path+file)
    