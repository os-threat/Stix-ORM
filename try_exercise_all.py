
from stixorm.module.initialise import sort_layers, load_typeql_data, setup_database, load_schema, load_markings

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

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
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
based_dir = "test/data/"
directories = {
    "stix": "standard",
    "os_threat": "os_threat/exercise",
    "oca": "oca/docs_data",
    "kestrel": "definitions/kestrel/schema/cti-oca.tql"
}

def try_oca_schema(schema_path):
    """ Test the OCA schema loading
        1. Clean the database
        2. Load all of the schemas
        3. Load the markings

    """
    setup_database(connection, True)
    for schema in schemas:
        schema_path = os.path.join(schema_path, schema)
        print(f'loading schema {schema_path}')
        load_schema(connection, schema_path)
    load_markings(connection)

def try_oca_stix(schema_path, data_path):
    """ Test the OCA STIX object creation
        1. Clean the database
        2. Load all of the schemas
        3. Load the markings
        4. Load the STIX objects

    """
    try_oca_schema(schema_path)
    stix_obj = parse(test_ident, False, import_type)
    print(f'object is {stix_obj}')
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, import_type)
    print(f'dep_match -> {dep_match}')
    print(f'dep_insert -> {dep_insert}')
    print(f'indep_ql -> {indep_ql}')
    print(f'core_ql -> {core_ql}')