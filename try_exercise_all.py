
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

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $stix-id isa stix-id; get $stix-id;'

import_type =  import_type_factory.get_all_imports()
all_imports = import_type_factory.get_all_imports()
base_dir = "test/data/"
proven = {    
    "stix": "examples"
}
directories = {
    "stix": "examples",
    "os_threat": "os-threat/examples",
    "oca": "oca/examples",
    "attack": "attack/examples",
    "mbc": "mbc/examples",
    "attack_flow": "attack_flow/examples"
}
test1 = "test_data"
test2 = "os-threat/examples"
test3 = "mbc/examples"
test4 = "attack_flow/examples"
test5 = "attack/examples"
test_dir = {
    "test": test2
}

frameworks = {
    "attack_enterprise": "attack/latest/enterprise-attack-17.1.json",
    "attack_ics": "attack/latest/ics-attack-17.1.json",
    "mbc": "mbc/framework/mbc.json"
}

def get_stix_ids(get_id_query = get_ids):
    """ Get all the stix-ids in a database, should be moved to typedb_lib file

    Returns:
        id_list : list of the stix-ids in the database
    """
    query = get_id_query
    g_uri = connection["uri"] + ':' + connection["port"]
    id_list = []
    with TypeDB. core_driver(g_uri) as client:
        with client.session(connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as read_transaction:
                logger.debug(f"\n\n query is -> {query}")
                answer_iterator = read_transaction.query.get(query)
                ids = [ans.get("stix-id") for ans in answer_iterator]
                for sid_obj in ids:
                    sid = sid_obj.as_attribute().as_attribute().get_value()
                    if sid in marking:
                        continue
                    else:
                        id_list.append(sid)
    return id_list

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
    typedb_sink = TypeDBSink(connection, True, import_type)
    id_list = []
    list_of_objects = []
    dirFiles = os.listdir(path)
    sorted_files = sorted(dirFiles)
    logger.info(sorted_files)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(path, s_file)):
            continue
        else:
            logger.info('\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            logger.info(f'==================== {s_file} ===================================')
            logger.info('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print('\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print(f'==================== {s_file} ===================================')
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            with open(os.path.join(path, s_file), mode="r", encoding="utf-8") as f:
                json_data = json.load(f)
                list_of_objects_in_file = convert_json_to_list(json_data)
                for element in list_of_objects_in_file:
                    #logger.info(f'element is {element}')
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
                        list_of_objects.append(element)
                # list_of_objects = list_of_objects + json_list
                logger.info(f'9999999999999999999999999 Add {len(list_of_objects_in_file)} 99999999999999999999999999999999999999999999')
                print(f'9999999999999999999999999 Add {len(list_of_objects_in_file)} 99999999999999999999999999999999999999999999')
    logger.info(f'\n\n\n===========================\nready to import -> {len(set(id_list))}')
    print(f'\n\n\n===========================\nready to import -> {len(set(id_list))}')
    typedb_sink.add(list_of_objects)

    # check how many got loaded
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    sorted_diff = sorted(list(id_diff))
    logger.info(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    logger.info(f'difference -> ')
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> ')
    for id_d in sorted_diff:
        logger.info(id_d)
        print(id_d)
    logger.info('===================================================\n\n')
    print('===================================================\n\n')

def exercise_all():
    """Exercise all data directories and frameworks.

    """
    # backdoor_add_dir(os.path.join(base_dir, test2))
    # typedb_sink = TypeDBSink(connection, True, import_type)
    # typedb_source = TypeDBSource(connection, import_type)
    for name, path in test_dir.items():
        logger.info("\n===================================================")
        logger.info(f'Exercising {name} components with data from {path}')
        print("\n===================================================")
        print(f'Exercising {name} components with data from {path}')
        # Here you would call the function to process the data
        # For example: process_data(name, path)
        exercise_each_file_directory(name, os.path.join(base_dir, path))
        # backdoor_add_dir(os.path.join(base_dir, path))

    for name, path in frameworks.items():
        # logger.info("\n===================================================")
        # logger.info(f'Loading {name} framework with data from {path}')
        # Here you would call the function to process the data
        # For example: process_data(name, path)
        pass


##############################################################################

# if this file is run directly, then start here
if __name__ == '__main__':
    exercise_all()