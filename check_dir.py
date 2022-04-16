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
# 150.230.11.93
data_path = "data/examples/"
file = "marking_definitions.json"

            
            

def compare_dir(dir):
    typedb_sink = TypeDBSink(connection, True, "Stix21")      
    typedb_source = TypeDBSource(connection, "Stix21")  
    for file in sorted(os.listdir(dir)):
        if file.endswith(".json"):
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print(f'------------------------------------------------- {file} import-------------------------------------------------')
            compare_file(dir+file, typedb_sink, typedb_source)
            print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
            
            


def compare_file(path, typedb_sink, typedb_source):
    with open(path, mode="r", encoding="utf-8") as f:
        json_text =  json.load(f)
        if isinstance(json_text, list):
            for item in json_text:
                stx_obj = parse(item)
                compare_obj(stx_obj, typedb_sink, typedb_source)
        else:        
            bundle = parse(json_text)
            stx_objs = bundle.objects
            for stx_obj in stx_objs:
                compare_obj(stx_obj, typedb_sink, typedb_source)
                
                
                
                
def compare_obj(stx_obj, typedb_sink, typedb_source):    
    # 1. Get the ID of the Stix Object       
    stix_id = stx_obj.id
    stix_type = stx_obj.type
    # 2. Add the Stix Object to the TypeDB
    typedb_sink.add(stx_obj)
    # 3. Query the Stix Object from the TypeDB
    return_obj = typedb_source.get(stix_id)
    ret_obj = parse(return_obj)
    print('===========================================================================================')
    print(f'------------------------------------------------- {stix_type} Stix import-------------------------------------------------')
    print(stx_obj.serialize(pretty=True))
    print(f'-------------------------------------------------- Stix Export from TypeDB --------------------------------------------------')
    print(ret_obj.serialize(pretty=True))
    print('===========================================================================================')
    
            
    
      



# if this file is run directly, then start here
if __name__ == '__main__':
    
    
    
    compare_dir(data_path)
    
    
