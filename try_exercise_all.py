
from stixorm.module.initialise import sort_layers, load_typeql_data, setup_database, load_schema, load_markings
from try_refactor import dict_to_typeql, backdoor_add_dir
import json
import os
import datetime
import csv
from typing import Dict
from stixorm.module.typedb import TypeDBSink, TypeDBSource
from typedb.driver import *
from stixorm.module.orm.import_objects import raw_stix2_to_typeql
from stixorm.module.orm.delete_object import delete_stix_object
from stixorm.module.orm.export_object import convert_ans_to_stix
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.parsing.conversion_decisions import get_embedded_match
from stixorm.module.initialise import sort_layers, load_typeql_data
from stixorm.module.definitions.stix21 import ObservedData, IPv4Address
from stixorm.module.definitions.os_threat import Feed, ThreatSubObject
from stixorm.module.orm.import_utilities import val_tql
from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.model.definitions import DefinitionName
stix_models = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
attack_models = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK)
os_threat_models = get_definition_factory_instance().lookup_definition(DefinitionName.OS_THREAT)
oca_models = get_definition_factory_instance().lookup_definition(DefinitionName.OCA)
mbc_models = get_definition_factory_instance().lookup_definition(DefinitionName.MBC)
attack_flow_models = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK_FLOW)
import copy

import logging

from timeit import default_timer as timer

#from stix.module.typedb_lib.import_type_factory import AttackDomains, AttackVersions

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)
#logger.addHandler(logging.StreamHandler())


# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type =  import_type_factory.get_all_imports()
all_imports = import_type_factory.get_all_imports()
base_dir = "test/data/"
proven = {    
    "stix": "standard"
}
directories = {
    "stix": "standard",
    "os_threat": "os-threat/exercise",
    "oca": "oca/docs_data",
    "attack": "mitre/test",
    "mbc": "mbc/examples",
    "attack_flow": "attack_flow/examples"
}

frameworks = {
    "attack_enterprise": "mitre/latest/enterprise-attack-17.1.json",
    "attack_ics": "mitre/latest/ics-attack-17.1.json",
    "mbc": "mbc/framework/mbc.json"
}

def convert_json_to_list(json_data: Union[dict, list]) -> List[dict]:
    """Convert JSON data to a list of objects.
    Inputs:
        json_data: The JSON data to convert
    Returns:
        A list of stix objects
    """
    if isinstance(json_data, dict):
        dict_type = json_data.get("type", None)
        if dict_type == "bundle":
            return json_data.get("objects", [])
        else:
            return []
    elif isinstance(json_data, list):
        return json_data
    return []


def exercise_each_file_directory(name: str, path: str):
    """Exercise each file in the directory
    Inputs:
        name: The name of the component
        path: The path to the data files
    """
    dirFiles = os.listdir(path)
    sorted_files = sorted(dirFiles)
    print(sorted_files)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(path, s_file)):
            continue
        else:
            id_list = []
            print('\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print(f'==================== {s_file} ===================================')
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            with open(os.path.join(path, s_file), mode="r", encoding="utf-8") as f:
                json_data = json.load(f)
                list_of_objects = convert_json_to_list(json_data)
                typedb_sink = TypeDBSink(connection, True, import_type)
                for element in list_of_objects:
                    #print(f'element is {element}')
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
                # list_of_objects = list_of_objects + json_list
                print(f'9999999999999999999999999 Add {len(list_of_objects)} 99999999999999999999999999999999999999999999')
                typedb_sink.add(list_of_objects)

def exercise_all():
    """Exercise all data directories and frameworks.

    """
    backdoor_add_dir(os.path.join(base_dir, "test_data"))
    # typedb_sink = TypeDBSink(connection, True, import_type)
    # typedb_source = TypeDBSource(connection, import_type)
    for name, path in directories.items():
        print("\n===================================================")
        print(f'Exercising {name} components with data from {path}')
        # Here you would call the function to process the data
        # For example: process_data(name, path)
        # # exercise_each_file_directory(name, os.path.join(base_dir, path))
        # backdoor_add_dir(os.path.join(base_dir, path))

    for name, path in frameworks.items():
        print("\n===================================================")
        print(f'Loading {name} framework with data from {path}')
        # Here you would call the function to process the data
        # For example: process_data(name, path)


##############################################################################

# if this file is run directly, then start here
if __name__ == '__main__':
    exercise_all()