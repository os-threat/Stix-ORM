import os
import json

from stixorm.module.initialise import sort_layers, load_typeql_data, setup_database, load_schema, load_markings

# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

schemas = [
    "definitions/stix21/schema/cti-schema-v2.tql",
    "definitions/attack/schema/cti-attack.tql",
    "definitions/os_threat/schema/cti-os-threat.tql",
    "definitions/kestrel/schema/cti-oca.tql"
    ]

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