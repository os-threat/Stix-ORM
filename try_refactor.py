import json
import os
import datetime
from typing import Dict
#import dateutil.parser
#from dateutil.parser import *
from stixorm.module.typedb import TypeDBSink, TypeDBSource
from typedb.driver import *
from stixorm.module.orm.import_objects import raw_stix2_to_typeql
from stixorm.module.orm.delete_object import delete_stix_object
from stixorm.module.orm.export_object import convert_ans_to_stix
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.parsing.conversion_decisions import get_embedded_match
from stixorm.module.generate_docs import configure_overview_table_docs, object_tables
from stixorm.module.initialise import sort_layers, load_typeql_data
from stixorm.module.definitions.stix21 import ObservedData, IPv4Address
from stixorm.module.definitions.os_threat import Feed, ThreatSubObject
from stixorm.module.orm.import_utilities import val_tql
from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.model.definitions import DefinitionName
stix_models = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
attack_models = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK)
os_threat_models = get_definition_factory_instance().lookup_definition(DefinitionName.OS_THREAT)
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

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $stix-id isa stix-id; get $stix-id;'


test_id = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
marking_id = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
file_id = 'file--364fe3e5-b1f4-5ba3-b951-ee5983b3538d'


def test_generate_docs():
    print("================================================================================")
    print("------------------------ Test Doc Generation ---------------------------------------------")
    configure_overview_table_docs(object_tables)


def backdoor_get(stix_id, _composite_filters=None):
    """Retrieve STIX object from file directory via STIX ID.
    Args:
        stix_id (str): The STIX ID of the STIX object to be retrieved.
        _composite_filters (FilterSet): collection of filters passed from the parent
            CompositeDataSource, not user supplied
    Returns:
        (STIX object): STIX object that has the supplied STIX ID.
            The STIX object is loaded from its json file, parsed into
            a python STIX object and then returned
    """
    try:
        obj_var, type_ql = get_embedded_match(stix_id, import_type)
        match = 'match ' + type_ql
        #logger.debug(f' typeql -->: {match}')
        g_uri = connection["uri"] + ':' + connection["port"]
        with TypeDB. core_driver(g_uri) as client:
            with client.session(connection["database"], SessionType.DATA) as session:
                with session.transaction(TransactionType.READ) as read_transaction:
                    answer_iterator = read_transaction.query.match(match)
                    #logger.debug((f'have read the query -> {answer_iterator}'))
                    stix_dict = convert_ans_to_stix(match, answer_iterator, read_transaction, import_type)
                    stix_obj = parse(stix_dict, import_type=import_type)
                    #logger.debug(f'stix_obj -> {stix_obj}')
                    with open("export_final.json", "w") as outfile:
                        json.dump(stix_dict, outfile)

    except Exception as e:
        logger.error(f'Stix Object Retrieval Error: {e}')
        stix_obj = None

    return stix_obj


def dict_to_typeql(stix_dict, import_type):
    """ From the old code base,
            - convert a stix dict into a Python object, based on import_type
            -   convert the object into TypeQL, with a dpendency object
    """
    #logger.debug(f"im about to parse \n")
    stix_obj = parse(stix_dict, False, import_type)
    logger.debug(f' i have parsed {stix_dict}\n')
    logger.debug(f"\n object type -> {type(stix_obj)} -> {stix_obj}")
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, import_type)
    logger.debug(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
    dep_obj["dep_match"] = dep_match
    dep_obj["dep_insert"] = dep_insert
    dep_obj["indep_ql"] = indep_ql
    dep_obj["core_ql"] = core_ql
    return dep_obj


def test_insert_statements(pahhway, stid):
    with open(pahhway, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        json_text = json_text["objects"]
        for stix_dict in json_text:
            if stix_dict['id'] == stid:
                dep_obj = dict_to_typeql(stix_dict, import_type)
                logger.debug(f'\ndep_match {dep_obj["dep_match"]} \ndep_insert {dep_obj["dep_insert"]} \nindep_ql {dep_obj["indep_ql"]} \ncore_ql {dep_obj["core_ql"]}')


def update_layers(layers, indexes, missing, dep_obj, cyclical):
    """ From the old codebase takes a layer and updates it, handling the layer zero case

    """
    if len(layers) == 0:
        # 4a. For the first record to order
        missing = dep_obj['dep_list']
        indexes.append(dep_obj['id'])
        layers.append(dep_obj)
    else:
        # 4b. Add up and return the layers, indexes, missing and cyclical lists
        add = 'add'
        layers, indexes, missing, cyclical = sort_layers(layers, cyclical, indexes, missing, dep_obj, add)
    return layers, indexes, missing, cyclical


def backdoor_add_dir(dirpath):
    """ Test the database initialisation function

    """
    layers = []
    indexes = []
    missing = []
    cyclical = []
    type_ql_list = []
    id_list = []
    obj_list = []
    dirFiles = os.listdir(dirpath)
    sorted_files = sorted(dirFiles)
    typedb_sink = TypeDBSink(connection, True, import_type)
    typedb_source = TypeDBSource(connection, import_type)
    logger.debug(sorted_files)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(dirpath, s_file)):
            continue
        else:
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                #json_text = json_text["objects"]
                length = len(json_text)
                i=0
                for element in json_text:
                    i += 1
                    logger.debug(f' processing {i} of {length}')
                    logger.debug(f'**********{type(element)}==={element}')
                    obj_list.append(element)
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)

                    dep_obj = dict_to_typeql(element, import_type)
                    # logger.debug('----------------------------------------------------------------------------------------------------')
                    # myobj1 = parse(element, False, import_type)
                    # logger.debug(myobj1.serialize(pretty=True))
                    # logger.debug(f'\n================\n{dep_obj["dep_list"]}')
                    # logger.debug(f'\ndep_match {dep_obj["dep_match"]} \ndep_insert {dep_obj["dep_insert"]} \nindep_ql {dep_obj["indep_ql"]} \ncore_ql {dep_obj["core_ql"]}')
                    # logger.debug('----------------------------------------------------------------------------------------------------')
                    layers, indexes, missing, cyclical = update_layers(layers, indexes, missing, dep_obj, cyclical)

    logger.debug(f'missing {missing}, cyclical {cyclical}')
    newlist = []
    duplist = []
    missing2 = []
    if missing != []:
        missing2 = [x for x in missing if x not in id_list]
        print(f'\n\n-----------------')
        print(f'missing ->{missing}')
        print(f'missing2 -> {missing2}')

    if missing2 == [] and cyclical == []:
        # add the layers into a list of strings
        for layer in layers:
            stid = layer["id"]
            if stid not in newlist:
                newlist.append(stid)
                dep_match = layer["dep_match"]
                dep_insert = layer["dep_insert"]
                indep_ql = layer["indep_ql"]
                core_ql = layer["core_ql"]
                print("\n&&&&&&&&&&&&&&&&&&&&&&&&&")
                print(f'{layer["id"]}      -> {layer["dep_list"]}')

                #print(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
                prestring = ""
                if dep_match != "":
                    prestring = "match " + dep_match
                upload_string = prestring + " insert " + indep_ql + dep_insert
                print(" ")
                print(upload_string)
                type_ql_list.append(upload_string)
            else:
                duplist.append(stid)

        # add list of strings to typedb
        load_typeql_data(type_ql_list, connection)
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    sorted_diff = sorted(list(id_diff))
    print(f'\n\n\n===========================\nduplist -> {duplist}')
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> ')
    for id_d in sorted_diff:
        print(id_d)


def backdoor_add(pahhway):
    """ Test the database initialisation function

    """
    typedb = TypeDBSink(connection, True, import_type)
    layers = []
    indexes = []
    missing = []
    cyclical = []
    type_ql_list = []
    id_list = []
    with open(pahhway, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        for stix_dict in json_text:
            dep_obj = dict_to_typeql(stix_dict, import_type)
            layers, indexes, missing, cyclical = update_layers(layers, indexes, missing, dep_obj, cyclical)
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print(f"layers -> {layers}")
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")

    print(f'missing {missing}, cyclical {cyclical}')
    if missing == [] and cyclical == []:
        # add the layers into a list of strings
        for layer in layers:
            stid = layer["id"]
            id_list.append(stid)
            dep_match = dep_obj["dep_match"]
            dep_insert = dep_obj["dep_insert"]
            indep_ql = dep_obj["indep_ql"]
            core_ql = dep_obj["core_ql"]
            #print(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
            prestring = ""
            if dep_match != "":
                prestring = "match " + dep_match
            upload_string = prestring + " insert " + indep_ql + dep_insert
            type_ql_list.append(upload_string)

        # add list of strings to typedb
        load_typeql_data(type_ql_list, connection)

    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


def test_initialise():
    """ Test the database initialisation function

    """
    typedb = TypeDBSink(connection, True, all_imports)


def load_file_list(path1, file_list):
    """ Load a list of files from a path, number of files can be restricted

    Args:
        path1 (): path
        file_list (): list of files
    """
    obj_list = []
    logger.debug(f' connection {connection}')
    typedb = TypeDBSink(connection, True, import_type)
    #print(f'files {file_list}')
    for i, f in enumerate(file_list):
        logger.debug(f'i have entered the file loop, time {i}')
        if i > 100:
            break
        else:
            with open((path1+f), mode="r", encoding="utf-8") as df:
                #print(f'I am about to history {f}')
                json_text = json.load(df)
                obj_list.extend(json_text)

    typedb.add(obj_list)


def load_file(fullname):
    """ Add a json file to typeDB

    Args:
        fullname (): path and filename
    """
    evidence_list = []
    logger.debug(f'inside history file {fullname}')
    typedb = TypeDBSink(connection, False, import_type)
    input_id_list=[]
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        #print(json_text["objects"])
        for stix_dict in json_text: #["objects"]:
            input_id_list.append(stix_dict.get("id", False))
        result = typedb.add(json_text)
    id_set = set(input_id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    for item in result:
        print(item.id + " " + str(item.status) + " " + str(item.message))


def check_object(fullname):
    logger.debug(f'inside history file {fullname}')
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb = TypeDBSink(connection, True, import_type)
        # first find identity
        for jt in json_text:
            if jt["type"] == "relationship":
                relationship = jt
            elif jt["type"] == "x-mitre-tactic":
                tactic =jt
            elif jt["type"] == "attack-pattern":
                if jt["x_mitre_is_subtechnique"] == True:
                    subtechnique = jt
                else:
                    technique = jt

        # try to make an object out of identity
        templist=[]
        templist.append(relationship)
        typedb.add(templist)
        # myobj1 = parse(subtechnique, False, import_type)
        # print(f'\n\n============> my subtechnique = {myobj1}<==================\n\n')
        # myobj2 = parse(technique, False, import_type)
        # print(f'\n\n============> my technique = {myobj2}<==================\n\n')
        # myobj3 = parse(relationship, False, import_type)
        # print(f'\n\n============> my relationship = {myobj3}<==================\n\n')
        # myobj4 = parse(tactic, False, import_type)
        # print(f'\n\n============> my tactic = {myobj4} <==================\n\n')


def test_get_del_dir_statements(dirpath):
    dirFiles = os.listdir(dirpath)
    sorted_files = sorted(dirFiles)
    for i, s_file in enumerate(sorted_files):
        if os.path.isdir(os.path.join(dirpath, s_file)) or i<0:
            continue
        else:
            file_list.append(s_file)
            #print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            #print(f'==================== {s_file} ===================================')
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                for jt in json_text:
                    stid = jt["id"]
                    query_id(stid)


def test_get_delete(fullname):
    #load_file(fullname)
    id_list = get_stix_ids()
    print(f"\n\n=============\n------{id_list}-------\n$$$$$$$$$$$$$$$$$$$$$\n")
    for inc, obj_id in enumerate(id_list):
        print(f'\n==========\n---------- {inc + 1} of {len(id_list)} -------\n===========')
        query_id(obj_id)
    print(f'id list -> {id_list}')


def query_id(stixid):
    """  Print out the match/insert and match/delete statements for any stix-id

    Args:
        stixid ():
    """
    typedb = TypeDBSource(connection, import_type)
    print(f'stixid -> {stixid}')
    #stix_dict = typedb.get(stixid)
    stix_dict = backdoor_get(stixid)
    stix_obj = stix_dict #parse(stix_dict)
    print(' ---------------------------Query Object----------------------')
    print(stix_obj.serialize(pretty=True))
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, import_type)
    print(' ---------------------------Insert Object----------------------')
    print(f'dep_match -> {dep_match}')
    print(f'dep_insert -> {dep_insert}')
    print(f'indep_ql -> {indep_ql}')
    print(f'core_ql -> {core_ql}')
    print("=========================== delete typeql below ====================================")
    del_match, del_tql = delete_stix_object(stix_obj, dep_match, dep_insert, indep_ql, core_ql, import_type)
    print(f'del_match -> {del_match}')
    print(f'del_tql -> {del_tql}')


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


def clean_db():
    """ Get all stix-ids and delete them

    """
    local_list = get_stix_ids()
    print(f'list -> {local_list}')
    for stid in local_list:
        print(f"\nid is -> {stid}\n")
        query_id(stid)
    typedb = TypeDBSink(connection, False, import_type)
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$ Ready for Delete $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    typedb.delete(local_list)
    print(f"len db ids before delete -> {len(local_list)}")
    print(f"db ids after delete -> {len(get_stix_ids())}")


def test_delete_dir(dirpath):
    """ Load an entire directory and delete all files except marking objects

    Args:
        dirpath (): path to directory to delete
    """
    dirFiles = os.listdir(dirpath)
    sorted_files = sorted(dirFiles)
    typedb_sink = TypeDBSink(connection, True, import_type)
    print(sorted_files)
    layers = []
    indexes = []
    missing = []
    cyclical = []
    obj_list = []
    input_id_list = []
    file_list = []
    for i, s_file in enumerate(sorted_files):
        if os.path.isdir(os.path.join(dirpath, s_file)) or i<0:
            continue
        else:
            file_list.append(s_file)
            #print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            #print(f'==================== {s_file} ===================================')
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                for stix_dict in json_text:
                    input_id_list.append(stix_dict.get("id", False))
                    obj_list.append(stix_dict)
                    # dep_obj = dict_to_typeql(stix_dict, import_type)
                    # layers, indexes, missing, cyclical = update_layers(layers, indexes, missing, dep_obj, cyclical)

                #typedb_sink.add(json_text)
                #print(json.dumps(json_text, indent=4))
                #print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')

    # print(f'missing {missing}, cyclical {cyclical}')
    # if missing == [] and cyclical == []:
    #     # add the layers into a list of strings
    #     for layer in layers:
    #         dep_match = dep_obj["dep_match"]
    #         dep_insert = dep_obj["dep_insert"]
    #         indep_ql = dep_obj["indep_ql"]
    #         core_ql = dep_obj["core_ql"]
    #         print(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
    #         prestring = ""
    #         if dep_match != "":
    #             prestring = "match " + dep_match
    #         upload_string = prestring + " insert " + indep_ql + dep_insert
    #         type_ql_list.append(upload_string)
    #
    #     # add list of strings to typedb
    #     load_typeql_data(type_ql_list, connection)
    typedb_sink.add(obj_list)
    print("**********************************************************************************")
    print("----------------------------------------------------------------------------------")
    print("============= Add is complete =====================================================")
    print("**********************************************************************************")
    stix_id_list = set(get_stix_ids())
    for stid in stix_id_list:
        print(f"\nid is -> {stid}\n")
        query_id(stid)

    print("**********************************************************************************")
    print("----------------------------------------------------------------------------------")
    print("============= Get is complete =====================================================")
    print("**********************************************************************************")
    typedb_sink.delete(stix_id_list)
    #clean_db()
    #print(f' files-> {file_list}')
    print(f"\n\nlen input ids -> {len(set(input_id_list))} ")
    print(f"len db ids before delete -> {len(stix_id_list)}")
    print(f"db ids after delete -> {len(get_stix_ids())}")


def test_delete(path):
    """ Load a single file and delete it

    Args:
        path (): the path and file name
    """
    obj_ids = []
    typedb = TypeDBSink(connection, True, import_type)
    with open(path, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb.add(json_text)

    local_list = get_stix_ids()
    typedb.delete(local_list)


def check_dir_ids(dirpath):
    """ Open a directory and history all the files,
    one at a time to the database and then check the ids

    Args:
        dirpath ():
    """
    id_list = []
    dirFiles = os.listdir(dirpath)
    sorted_files = sorted(dirFiles)
    print(sorted_files)
    typedb_sink = TypeDBSink(connection, True, import_type)
    typedb_source = TypeDBSource(connection, import_type)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(dirpath, s_file)):
            continue
        else:
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print(f'==================== {s_file} ===================================')
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                for element in json_text:
                    print(f'**********==={element}')
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
                typedb_sink.add(json_text)
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


def check_dir_ids2(dirpath):
    """ Open a directory and history all the files,
    creating a list of objects first and then adding them to the db

    Args:
        dirpath ():
    """
    id_list = []
    obj_list = []
    dirFiles = os.listdir(dirpath)
    sorted_files = sorted(dirFiles)
    #print(sorted_files)
    typedb_sink = TypeDBSink(connection, True, import_type)
    typedb_source = TypeDBSource(connection, import_type)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(dirpath, s_file)):
            continue
        else:
            # print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            # print(f'==================== {s_file} ===================================')
            # print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                for element in json_text:
                    #print(f'**********==={element}')
                    obj_list.append(element)
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
    typedb_sink.add(obj_list)
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
    print(f'==================== Add is Complete ===================================')
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


def check_dir(dirpath):
    """ Open a directory and history all the files, optionally printing them

    Args:
        dirpath ():
    """
    id_list = []
    dirFiles = os.listdir(dirpath)
    list_of_objects = []
    sorted_files = sorted(dirFiles)
    print(sorted_files)
    typedb_sink = TypeDBSink(connection, True, import_type)
    typedb_source = TypeDBSource(connection, import_type)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(dirpath, s_file)):
            continue
        else:
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print(f'==================== {s_file} ===================================')
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                testtime = datetime.now()
                print(f"I am opening the file {testtime}")
                json_list = json.load(f)
                #json_list = json_list["objects"]
                for element in json_list:
                    #print(f'element is {element}')
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
                list_of_objects = list_of_objects + json_list
    print(f'9999999999999999999999999 Add {len(list_of_objects)} 99999999999999999999999999999999999999999999')
    typedb_sink.add(list_of_objects)
    print(f'==================== List is added  ===================================')
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    sorted_diff = sorted(list(id_diff))
    print(f'difference -> ')
    for id_d in sorted_diff:
        print(id_d)


def cert_dict(cert_root, certs):
    for cert in certs:
        print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        print(f'==================== {cert} ===================================')
        print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        cert_test(cert_root + cert)


def cert_test(dirpath):
    dirs = [
        "consumer_example/",
        "consumer_test/",
        "producer_example/",
        "producer_test/"
    ]
    for d in dirs:
        #print(f'############## {dirpath+d} #################')
        print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
        #print(f'handler {logger.handlers}')
        print('----------------------------------------')
        dirFiles = os.listdir(dirpath+d)
        for s_file in dirFiles:
            if os.path.isdir(os.path.join((dirpath+d), s_file)):
                continue
            else:
                local_list1 = []
                print(f's-file {s_file}')
                with open(os.path.join(dirpath+d, s_file), mode="r", encoding="utf-8") as f:
                    json_text = json.load(f)
                    for l in json_text:
                        local_list1.append(l["id"])
                print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
                print(f'==================== {dirpath+d+s_file} ===================================')
                print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
                load_file(dirpath+d+s_file)
                local_list = get_stix_ids()
                print(f'my id list -> {local_list}')
                print('========================= I am starting deletion ===========================================')
                typedb = TypeDBSink(connection, False, import_type)
                typedb.delete(local_list)
                local_list2 = get_stix_ids()
                print("******************************************")
                print(f'\n\nmy initial list is -> {local_list1}')
                print(f'\n\nmy returned list is -> {local_list}')
                print(f'\n\nmy final list is -> {local_list2}')
                print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')


def test_get_ids(connection, import_type):
    typedb_sink = TypeDBSink(connection, False, import_type)
    my_id_list = typedb_sink.get_stix_ids()
    print(f'myidlist {my_id_list}')

def test_get(stixid):
    typedb_source = TypeDBSource(connection, import_type)
    stix_obj = typedb_source.get(stixid, None)
    return stix_obj


def test_get_file(fullname):
    load_file(fullname)
    typedb_sink = TypeDBSink(connection, False, import_type)
    stid_list = typedb_sink.get_stix_ids()
    for stid in stid_list:
        stix_obj = test_get(stid)


def test_json(fullname):
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        for jt in json_text:
            print("===========================================")
            print(jt)



def test_auth():
    # import_type = import_type_factory.create_import(stix_21=True,
    #                                                 os_hunt=True,
    #                                                 os_intel=True,
    #                                                 cacao=True,
    #                                                 attack_domains=[AttackDomains.ENTERPRISE_ATTACK, AttackDomains.ICS_ATTACK, AttackDomains.MOBILE_ATTACK],
    #                                                 attack_versions=[AttackVersions.V12_1])

    auth = authorised_mappings(import_type)
    print("===========================================")
    print(auth)

# ObservedData, IPv4Address, Feed, ThreatSubObject
###################################################################################
#
# Setup Feeds import and update code
#
##################################################################################
def test_feeds():
    osthreat = "data/os-threat/feed-example/example.json"
    # # datetime1 = dateutil.parser.isoparse("2020-10-19T01:01:01.000Z")
    # # datetime2 = dateutil.parser.isoparse("2020-10-20T01:01:01.000Z")
    # # datetime3 = dateutil.parser.isoparse("2020-10-21T01:01:01.000Z")
    # typedb_source = TypeDBSource(connection, import_type)
    # typedb_sink = TypeDBSink(connection, True, import_type)
    # with open(osthreat, mode="r", encoding="utf-8") as f:
    #     json_text = json.load(f)
    #     # first lets create the feed
    #     feed_id = create_feed(json_text[0], typedb_sink, datetime1)
    #     print(f'feed id -> {feed_id}')
    #     update_feed(feed_id, json_text[1], datetime2, typedb_source, typedb_sink)


def update_feed(feed_id, local_list, loc_datetime, typedb_source, typedb_sink):
    # get the feed
    sco_map = {}
    sco_loaded_list = []
    feed_obj = typedb_source.get(feed_id, None)
    # get the observed data objects
    loc_contents = feed_obj["contents"]
    for loc_content in loc_contents:
        observed_id = loc_content["object_ref"] # get the observed data id
        observed_obj = typedb_source.get(observed_id, None)
        sco_list = observed_obj["object_refs"]
        # we make the assumption there is only one sco for every observed-data object
        for sco in sco_list:
            sco_obj = typedb_source.get(sco, None)
            sco_map[sco_obj["value"]] = observed_obj

    # build the list of scos that are laoded already
    sco_loaded_list = list(sco_map.keys())
    set_sco_loaded = set(sco_loaded_list)
    set_new_sco = set(local_list)
    update_date_list = list(set_sco_loaded & set_new_sco)
    revoke_list = list(set_sco_loaded - set_new_sco)
    insert_list = list(set_new_sco - set_sco_loaded)
    # plus new ips
    print(f'\n==== revoke =====\n{revoke_list}')
    revoke_observed(feed_id, revoke_list, sco_map)
    print(f"\n==== update =====\n{update_date_list}")
    update_observed_and_feed_dates(feed_id, update_date_list, sco_map, loc_datetime)
    print(f'\n==== insert =====\n{insert_list}')
    insert_observed(feed_id, insert_list, loc_datetime, typedb_sink)
    print("===============================================")


def insert_observed(feed_id, insert_list, loc_datetime, typedb_sink):
    ips = []
    observed = []
    obs_ids = []
    insert_tql_list = []
    for ipaddr in insert_list:
        ip = IPv4Address(value=ipaddr)
        ips.append(ip)
        obs = ObservedData(
            first_observed=loc_datetime,
            last_observed=loc_datetime,
            number_observed=1,
            object_refs =[ip.id]
        )
        observed.append(obs)
        obs_ids.append(obs.id)

    add_list = ips + observed
    typedb_sink.add(add_list)

    for obs_id in obs_ids:
        insert_tql = 'match $obs isa observed-data, has stix-id "' + obs_id + '";'
        insert_tql += '$feed isa feed, has stix-id "' + feed_id + '";' # get the feed
        insert_tql += 'insert $sub isa threat-sub-object, has created ' + val_tql(loc_datetime) + ','
        insert_tql += 'has modified ' + val_tql(loc_datetime) + ';'
        insert_tql += '$objref (container:$sub,content:$obs) isa obj-ref;'
        insert_tql += '$content (content:$sub, feed-owner:$feed) isa feed-content;'
        insert_tql_list.append(insert_tql)

    insert_typeql_data(insert_tql_list, connection)


def revoke_observed(feed_id, revoke_list, sco_map):
    insert_tql_list = []
    update_tql_list = []
    for rev in revoke_list:
        observed_obj = sco_map[rev]
        if not getattr(observed_obj, "revoked", False):
            # revoke the observed data object, but the revoke property is there and is false, so update to make it true
            revoke_tql = 'match $x isa observed-data, has stix-id "' + observed_obj['id'] + '";'
            revoke_tql += 'insert $x has revoked true;'
            insert_tql_list.append(revoke_tql)

    #update_typeql_data(update_tql_list, connection)
    insert_typeql_data(insert_tql_list, connection)


def update_observed_and_feed_dates(feed_id, update_date_list, sco_map, loc_datetime):
    update_tql_list = []
    obs_id_list = []
    feed_update_list = []
    # update the observed data objects
    for up in update_date_list:
        observed_obj = sco_map[up]
        obs_id_list.append(observed_obj["id"])
        # update the observed data object, modified, and last observed and feed modified
        update_obs_tql = 'match $obs isa observed-data, has stix-id "' + observed_obj['id'] + '",'
        update_obs_tql += 'has last-observed $last_obs, has modified $mod, has number-observed $num_obs;'
        update_obs_tql += 'delete $obs has $last_obs; $obs has $mod; $obs has $num_obs;'
        update_obs_tql += 'insert $obs has last-observed ' + val_tql(loc_datetime) + ';'
        update_obs_tql += '$obs has modified ' + val_tql(loc_datetime) + ';' # this is the observed data object
        update_obs_tql += '$obs has number-observed ' + str(observed_obj['number_observed'] + 1) + ';'
        update_tql_list.append(update_obs_tql)

    # update the threat sub object
    for obs_id in obs_id_list:
        update_threat_tql = 'match $feed isa feed, has stix-id "' + feed_id + '";'
        update_threat_tql += '$obs isa observed-data, has stix-id "' + obs_id + '";'
        update_threat_tql += '$threat isa threat-sub-object, has modified $mod;'
        update_threat_tql += '$objref (container:$threat,content:$obs) isa obj-ref;'
        update_threat_tql += '$content (content:$threat, feed-owner:$feed) isa feed-content;'
        update_threat_tql += 'delete $threat has $mod;'
        update_threat_tql += 'insert $threat has modified ' + val_tql(loc_datetime) + ';'
        feed_update_list.append(update_threat_tql)

    # update the feed object modified date
    update_feed_tql = 'match $feed isa feed, has stix-id "' + feed_id + '";'
    update_feed_tql += '$feed has modified $mod;'
    update_feed_tql += 'delete $feed has $mod;'
    update_feed_tql += 'insert $feed has modified ' + val_tql(loc_datetime) + ';' # this is the feed object
    feed_update_list.append(update_feed_tql)
    # update the typeql
    update_typeql_data(update_tql_list, connection)
    update_typeql_data(feed_update_list, connection)


def create_feed(local_list, typedb_sink, loc_datetime):
    ips = []
    observed = []
    threatsubobj = []
    for ipaddr in local_list:
        ip = IPv4Address(value=ipaddr)
        ips.append(ip)
        obs = ObservedData(
            first_observed=loc_datetime,
            last_observed=loc_datetime,
            number_observed=1,
            object_refs =[ip.id]
        )
        observed.append(obs)
        sub = ThreatSubObject(
            object_ref=obs.id,
            created=loc_datetime,
            modified=loc_datetime
        )
        threatsubobj.append(sub)

    feed = Feed(
        name="OS Threat Feed",
        description="OS Threat Test Feed",
        created=loc_datetime,
        contents=[
            threatsubobj[0],
            threatsubobj[1],
            threatsubobj[2],
            threatsubobj[3]
        ]
    )
    add_list = ips + observed + [feed]
    typedb_sink.add(add_list)
    return feed.id


def update_typeql_data(data_list, stix_connection: Dict[str, str]):
    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB. core_driver(url) as client:
        # Update the data in the database
        with client.session(stix_connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.WRITE) as update_transaction:
                logger.debug(f'==================== updating feed concepts =======================')
                for data in data_list:
                    logger.debug(f'\n\n{data}\n\n')
                    insert_iterator = update_transaction.query.update(data)

                    logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                    for result in insert_iterator:
                        logger.info(f'typedb response ->\n{result}')

                update_transaction.commit()


def insert_typeql_data(data_list, stix_connection: Dict[str, str]):
    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB. core_driver(url) as client:
        # Update the data in the database
        with client.session(stix_connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.WRITE) as insert_transaction:
                logger.debug(f'=========== inserting feed concepts ===========================')
                for data in data_list:
                    logger.debug(f'\n\n{data}\n\n')
                    insert_iterator = insert_transaction.query.insert(data)

                    logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                    for result in insert_iterator:
                        logger.info(f'typedb response ->\n{result}')

                insert_transaction.commit()

###############################################################################
#
#  Generic Subgraph -get
#  Runs a bit slow, needs optimising
##################################################################################
def try_subgraph_get(fullname):
    check_id = "report--f2b63e80-b523-4747-a069-35c002c690db"
    #connection["database"] = "local"
    typedb_sink = TypeDBSink(connection, True, import_type)
    typedb = TypeDBSource(connection, import_type)
    input_id_list=[]
    check_id_list=[]
    subgraph_objs=[]
    subgraph_ids=[]
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        # for stix_dict in json_text:
        #     input_id_list.append(stix_dict.get("id", False))
        file_length = len(json_text["objects"])
        typedb_sink.add(json_text)
    check_id_list = typedb_sink.get_stix_ids()
    start = timer()
    subgraph_objs, obj_id_set, i=get_subgraph(check_id, connection)
    end = timer()
    for obj in subgraph_objs:
        subgraph_ids.append(obj.get("id", False))

    print("************** Report ****************************")
    print(end - start)  # Time in seconds
    print(f"file length is {file_length}")
    print(f"subgraph_objs length is {len(subgraph_objs)}")
    print(f"increment number is {i}")
    print(f"obj_id_set length is {len(obj_id_set)}")
    print(f'\n\nmy initial list is -> {input_id_list}')
    print(f'\n\nmy check list is -> {check_id_list}')
    print(f'\n\nmy subgraph list is -> {subgraph_ids}')
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')

    check_id = "malware--69101c2f-da92-47af-b402-7c60a39a982f"
    start2 = timer()
    subgraph_objs, obj_id_set, i=get_subgraph(check_id, connection)
    end2 = timer()
    for obj in subgraph_objs:
        subgraph_ids.append(obj.get("id", False))

    print("************** malware ****************************")
    print(end2 - start2)  # Time in seconds
    print(f"file length is {file_length}")
    print(f"subgraph_objs length is {len(subgraph_objs)}")
    print(f"increment number is {i}")
    print(f"obj_id_set length is {len(obj_id_set)}")
    print(f'\n\nmy initial list is -> {input_id_list}')
    print(f'\n\nmy check list is -> {check_id_list}')
    print(f'\n\nmy subgraph list is -> {subgraph_ids}')
    print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')


def get_subgraph(obj_id, connection):
    i=0
    typedb = TypeDBSource(connection, import_type)
    obj_list = []
    obj_id_set = set()
    # get initial object
    init_obj = typedb.get(obj_id)
    obj_list, obj_id_set, i = expand_subgraph(init_obj, obj_list, obj_id_set, connection, i)
    return obj_list, obj_id_set, i


unique_types = ["relationship","grouping","incident","note","observed-data", "opinion","report"]


def expand_subgraph(local_obj, obj_list, obj_id_set, connection, i):
    typedb = TypeDBSource(connection, import_type)
    if local_obj.get("id", False) not in obj_id_set:
        local_type = local_obj["type"]
        emb_id_list = []
        sro_id_list = []
        owner_id_list = []
        total_list = []
        sightings_id_list = []
        obj_list.append(local_obj)
        obj_id_set.add(local_obj["id"])
        emb_id_list, i = get_embed_ids(local_obj, i)
        if local_type == "observed-data":
            sightings_id_list, i = get_sightings(local_obj, connection, local_type, i)
        elif local_type == "indicator" or local_type == "malware":
            sightings_id_list, i = get_sightings(local_obj, connection, local_type, i)
        elif local_type == "identity" or local_type == "location":
            sightings_id_list, i = get_sightings(local_obj, connection, local_type, i)
        else:
            pass
        if local_type != "relationship" or local_type != "sighting":
            sro_id_list, i = get_sros(local_obj, connection, i)
        if local_type in unique_types:
            owner_id_list, i = get_owners(local_obj, connection, i)
        total_list = emb_id_list + sro_id_list + owner_id_list + sightings_id_list
        new_objects = list(set(total_list) - obj_id_set)
        for new_obj in new_objects:
            new_obj = typedb.get(new_obj)
            obj_list, obj_id_set, i = expand_subgraph(new_obj, obj_list, obj_id_set, connection, i)
    return obj_list, obj_id_set, i


def get_sightings(local_obj, connection, local_type, i):
    i += 1
    local_ids = []
    auth = authorised_mappings(import_type)
    # find object details
    local_id = local_obj["id"]
    # find typeql name
    match_tql = "match "
    if local_type == "observed-data":
        match_tql += '$obs isa observed-data, has stix-id "' + local_id + '";'
        match_tql += " $sight (observed:$obs) isa sighting, has stix-id $sight_id;"
    elif local_type == "indicator" or local_type == "malware":
        match_tql += '$sdo isa stix-domain-object, has stix-id "' + local_id + '";'
        match_tql += " $sight (sighting-of:$sdo) isa sighting, has stix-id $sight_id;"
    elif local_type == "identity" or local_type == "location":
        match_tql += '$ident isa identity, has stix-id "' + local_id + '";'
        match_tql += " $sight (where-sighted:$ident) isa sighting, has stix-id $sight_id;"

    else:
        raise ValueError(f"Unknown type in get_owners function {local_type}")
    # find embedded owners
    match_tql += " get $sight_id;"
    local_ids = local_ids + get_id_list(match_tql, connection, "sight_id")
    logger.debug(f"for {local_id} get_sightings: {local_ids}")
    return local_ids, i


def get_owners(local_obj, connection, i):
    i += 1
    local_ids = []
    auth = authorised_mappings(import_type)
    # find object details
    local_type = local_obj["type"]
    local_id = local_obj["id"]
    # find typeql name
    match_tql = "match "
    if local_type in auth["types"]["sdo"]:
        tql_type = "stix-domain-object"
        tql_var = "$down"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    elif local_type in auth["types"]["sro"] or local_type == "relationship":
        tql_type = "stix-core-relationship"
        tql_var = "$down"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    elif local_type in auth["types"]["sco"]:
        tql_type = "stix-cyber-observable-object"
        tql_var = "$down"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    elif local_type in auth["types"]["meta"]:
        tql_type = "marking-definition"
        tql_var = "$down"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    else:
        raise ValueError(f"Unknown type in get_owners function {local_type}")
    # find embedded owners
    match_tql += " $up isa stix-domain-object, has stix-id $up_id;"
    match_tql += f" (owner:$up, pointed-to: $down) isa embedded; get $up_id;"
    local_ids = local_ids + get_id_list(match_tql, connection, "up_id")
    logger.debug(f"for {local_id} get_owners: {local_ids}")
    return local_ids, i


def get_id_list(match_tql, connection, variable):
    g_uri = connection["uri"] + ':' + connection["port"]
    id_list = []
    with TypeDB.core_client(g_uri) as client:
        with client.session(connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as read_transaction:
                answer_iterator = read_transaction.query.match(match_tql)
                ids = [ans.get(variable) for ans in answer_iterator]
                for sid_obj in ids:
                    sid = sid_obj.get_value()
                    if sid in marking:
                        continue
                    else:
                        id_list.append(sid)
    return id_list


def get_sros(local_obj, connection, i):
    i += 1
    local_ids = []
    auth = authorised_mappings(import_type)
    # find object details
    local_type = local_obj["type"]
    local_id = local_obj["id"]
    print("***********************************")
    print(local_type)
    print(local_id)
    print("***********************************")
    # find typeql name
    match_tql = "match "
    if local_type in auth["types"]["sdo"]:
        tql_type = "stix-domain-object"
        tql_var = "$side"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    elif local_type in auth["types"]["sro"] or local_type == "relationship":
        return [], i
    elif local_type in auth["types"]["sco"]:
        tql_type = "stix-cyber-observable-object"
        tql_var = "$side"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    elif local_type in auth["types"]["meta"]:
        tql_type = "marking-definition"
        tql_var = "$side"
        match_tql += f"{tql_var} isa {tql_type}, has stix-id \"{local_id}\";"
    else:
        raise ValueError(f"Unknown type in get_sro function {local_type}")
    # find embedded owners
    match_tql += " $sro isa stix-core-relationship, has stix-id $sro_id;"
    match_tql += "{$sro (source:$side) isa stix-core-relationship;} or "
    match_tql += " {$sro (target:$side) isa stix-core-relationship;}; get $sro_id;"
    local_ids = local_ids + get_id_list(match_tql, connection, "sro_id")
    logger.debug(f"for {local_id} get_SRO's {local_ids}")
    return local_ids, i



def get_embed_ids(init_obj, i):
    local_ids = []
    i += 1
    for key, prop in init_obj.items():
        if key == "id":
            continue
        elif isinstance(prop, list):
            local_ids = local_ids + process_list(prop)
        elif isinstance(prop, dict):
            local_ids = local_ids + get_embed_ids(prop)
        elif isinstance(prop, str):
            local_ids = local_ids + process_str(prop)
        else:
            continue
    return local_ids, i


def process_list(prop):
    local_ids = []
    for element in prop:
        if isinstance(element, dict):
            local_ids = local_ids + get_embed_ids(element)
        elif isinstance(element, str):
            local_ids = local_ids + process_str(element)
        else:
            continue
    return local_ids


def process_str(prop):
    local_id = []
    auth = authorised_mappings(import_type)
    test_list = auth["tql_types"]["sdo"] + auth["tql_types"]["sro"] + auth["tql_types"]["sco"] + ["relationship"]
    if "--" in prop:
        tmp_source = prop.split('--')[0]
        if tmp_source in test_list:
            local_id.append(prop)
    return local_id


def test_get_embedded(obj_id):
    typedb = TypeDBSource(connection, import_type)
    obj_list = []
    emb_id_list = []
    sro_id_list = []
    # get initial object
    init_obj = typedb.get(obj_id)
    emb_id_list = get_embed_ids(init_obj)
    obj_list.append(init_obj["id"])
    obj_list.append(init_obj["created_by_ref"])
    obj_list = obj_list + init_obj["object_refs"]
    missing = set(obj_list) - set(emb_id_list)
    print("==================================================================")
    print(emb_id_list)
    print("==================================================================")
    print(len(emb_id_list))
    print(len(obj_list))
    print("==================================================================")
    print(missing)

######################################################################################
#
# Setup Nodes and Edges Array Stuff for Force Graph Display - including icons
#
########################################################################################
def try_nodes_and_edges():
    nodes_edges = {}
    with open(reports + poison, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        obj_list = json_text["objects"]
        print(obj_list[0])
        nodes_edges = nodes_and_edges(obj_list)
        with open("n_and_e.json", 'w') as outfile:
            json.dump(nodes_edges, outfile)


def nodes_and_edges(obj_list):
    nodes_edges = {}
    nodes = []
    edges = []
    for obj in obj_list:
        if obj["type"] == "relationship":
            edges = setup_edges(obj, edges)
        else:
            nodes, edges = setup_nodes(obj, nodes, edges)
    check_icons = []
    legend = []
    for node in nodes:
        if node["icon"] not in check_icons:
            check_icons.append(node["icon"])
            layer = {}
            layer["icon"] = node["icon"]
            layer["label"] = node["label"]
            legend.append(layer)
    nodes_edges["nodes"] = nodes
    nodes_edges["edges"] = edges
    nodes_edges["legend"] = legend
    return nodes_edges


def setup_edges(obj, edges):
    edge = {}
    edge["id"] = obj["id"]
    edge["type"] = "relationship"
    edge["label"] = obj["relationship_type"]
    edge["source"] = obj["source_ref"]
    edge["target"] = obj["target_ref"]
    edges.append(edge)
    return edges


def setup_nodes(obj, nodes, edges):
    obj_id = obj["id"]
    node = {}
    node["id"] = obj_id
    node["original"] = copy.deepcopy(obj)
    edges = find_embedded(obj, edges, obj_id)
    node = find_icon(obj, node)
    nodes.append(node)
    return nodes, edges


def find_embedded(obj, edges, obj_id):
    auth = authorised_mappings(import_type)
    for key, prop in obj.items():
        if key == "id":
            continue
        elif key in auth["reln_name"]["embedded_relations"]:
            edges = extract_ids(key, prop, edges, obj_id)
        elif isinstance(prop, list):
            edges = embedded_list(key, prop, edges, obj_id)
        elif isinstance(prop, dict):
            edges = find_embedded(prop, edges, obj_id)
        else:
            continue
    return edges


def embedded_list(key, prop, edges, obj_id):
    logger.debug(f"embedded_list {key} {prop}")
    for pro in prop:
        if isinstance(pro, dict):
            edges = find_embedded(pro, edges, obj_id)
        else:
            continue
    return edges


def extract_ids(key, prop, edges, obj_id):
    auth = authorised_mappings(import_type)
    for ex in auth["reln"]["embedded_relations"]:
        if ex["rel"] == key:
            label = ex["label"]
            source_owner = ex["owner-is-source"]
    edge = {"label": label, "type": "embedded"}
    if isinstance(prop, list):
        for pro in prop:
            if pro.split('--')[0] == "relationship":
                continue
            elif source_owner:
                edge["source"] = obj_id
                edge["target"] = pro
                edges.append(copy.deepcopy(edge))
            else:
                edge["source"] = pro
                edge["target"] = obj_id
                edges.append(copy.deepcopy(edge))
    else:
        if source_owner:
            edge["source"] = obj_id
            edge["target"] = prop
        else:
            edge["source"] = prop
            edge["target"] = obj_id
        edges.append(copy.deepcopy(edge))
    return edges


def find_icon(stix_object, node):
    auth = authorised_mappings(import_type)
    logger.debug(f'stix object type {stix_object["type"]}\n')
    label = ""
    icon = ""
    auth_types = copy.deepcopy(auth["types"])
    if stix_object["type"] in auth_types["sdo"]:
        logger.debug(f' going into sdo ---? {stix_object}')
        icon, label = sdo_icon(stix_object)
    elif stix_object["type"] in auth_types["sco"]:
        logger.debug(f' going into sco ---> {stix_object}')
        icon, label = sco_icon(stix_object)
    elif stix_object["type"] in auth_types["sro"]:
        logger.debug(f' going into sro ---> {stix_object}')
        icon, label = sro_icon(stix_object)
    elif stix_object["type"] == 'marking-definition':
        icon, label = meta_icon(stix_object)
    else:
        logger.error(f'object type not supported: {stix_object.type}, import type {import_type}')
    node["icon"] = icon
    node["label"] = label
    return node


def sdo_icon(stix_object):
    sdo_type = stix_object["type"]
    label = sdo_type
    icon_type = ""
    attack_type = ""
    attack_object = False if not stix_object.get("x_mitre_version", False) else True
    if attack_object:
        sub_technique = False if not stix_object.get("x_mitre_is_subtechnique", False) else True
        if sdo_type[:7] == "x-mitre":
            attack_type = sdo_type[8:]
        elif sdo_type == "attack-pattern":
            attack_type = "technique"
            if sub_technique:
                attack_type = "subtechnique"
        elif sdo_type == "course-of-action":
            attack_type = "mitigation"
        elif sdo_type == "intrusion-set":
            attack_type = "group"
        elif sdo_type == "malware" or sdo_type == "tool":
            attack_type = "software"
        elif sdo_type == "campaign":
            attack_type = "campaign"
        else:
            attack_type = "unknown"

        if "attack-" in attack_type:
            pass
        else:
            attack_type = "attack-" + attack_type
        icon_type = attack_type
    else:
        if sdo_type == "identity":
            if stix_object.get("identity_class", False):
                if stix_object["identity_class"] == "individual":
                    icon_type = "identity-individual"
                elif stix_object["identity_class"] == "organization":
                    icon_type = "identity-organization"
                elif stix_object["identity_class"] == "class":
                    icon_type = "identity-class"
                elif stix_object["identity_class"] == "system":
                    icon_type = "identity-system"
                elif stix_object["identity_class"] == "group":
                    icon_type = "identity-group"
                else:
                    icon_type = "identity-unknown"
            else:
                icon_type = "identity-unknown"

        elif sdo_type == "malware":
            if stix_object.get("is_family", False):
                icon_type = "malware-family"
            else:
                icon_type = "malware"
        else:
            icon_type = sdo_type
    return icon_type, label


def sco_icon(stix_object):
    sco_type = stix_object["type"]
    label = stix_object.get("name", "")
    if sco_type == "email-message":
        if stix_object.get("is_multipart", False):
            icon_type = "email-message-mime"
            label = stix_object.get("subject", "")
        else:
            icon_type = "email-message"
            label = stix_object.get("subject", "")
    elif sco_type == "file":
        if stix_object["extensions"].get("archive-ext", False):
            icon_type = "file-archive"
            label = stix_object.get("name", "")
        elif stix_object["extensions"].get("pdf-ext", False):
            icon_type = "file-pdf"
            label = stix_object.get("name", "")
        elif stix_object["extensions"].get("raster-image-ext", False):
            icon_type = "file-img"
            label = stix_object.get("name", "")
        elif stix_object["extensions"].get("windows-pebinary-ext", False):
            icon_type = "file-bin"
            label = stix_object.get("name", "")
        elif stix_object["extensions"].get("ntfs-ext", False):
            icon_type = "file-ntfs"
            label = stix_object.get("name", "")
        else:
            icon_type = "file"
            label = stix_object.get("name", "")
    elif sco_type == "network-traffic":
        if stix_object["extensions"].get("http-request-ext", False):
            icon_type = "network-traffic-http"
            label = "http-request"
        elif stix_object["extensions"].get("icmp-ext", False):
            icon_type = "network-traffic-icmp"
            label = "icmp"
        elif stix_object["extensions"].get("tcp-ext", False):
            icon_type = "network-traffic-tcp"
            label = "tcp"
        elif stix_object["extensions"].get("sock-ext", False):
            icon_type = "network-traffic-sock"
            label = "socket"
        else:
            icon_type = "network-traffic"
            for prot in stix_object["protocols"]:
                label += prot + ", "
    elif sco_type == "user-account":
        if stix_object["extensions"].get("unix-account-ext", False):
            icon_type = "user-account-unix"
            label = "unix-account"
        else:
            icon_type = "user-account"
            label = "standard-account"
    else:
        icon_type = sco_type
        if sco_type == "artifact":
            label = stix_object.get("mime_type", "")
        elif sco_type == "directory":
            label = stix_object.get("path", "")
        elif sco_type in ["domain-name", "email-addr", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex", "url"]:
            label = stix_object.get("value", "")
        elif sco_type == "process":
            if stix_object["extensions"].get("windows-process-ext", False):
                label = "windows process"
            elif stix_object["extensions"].get("windows-service-ext", False):
                label = "windows service"
            else:
                label = "standard process"
        elif sco_type == "windows-registry-key":
            label = stix_object.get("key", "")
        elif sco_type == "x509-certificate":
            label = stix_object.get("serial_number", "")
    return icon_type, label


def sro_icon(stix_object):
    sro_type = stix_object["type"]
    if sro_type == "sighting":
        icon_type = "sighting"
        label = "sighting"
    else:
        icon_type = "relationship"
        label = stix_object.get("retlationship_type", "relationship")
    return icon_type, label


def meta_icon(stix_object):
    return "marking-definition", stix_object.get("definition_type", "")

###################################################################################
#
#  Build TypeDB Source
#
#############################################################################

compare = {
    "GT" : " > ",
    "LT": " < ",
    "EQ": " ",
    "GE": " >= ",
    "LE": " <= ",
    "NE": " != "
}

def get_list(stix_id_list):
    '''
    TypeDBSource Method
    To be poarallelised and sped-up by Denis, main

    Args:
        - stix_id_list ([stix-id]) - a list of valid stix-id's that exists in the database

    Returns
        - list of stix objects or an error message
    '''
    obj_list = []
    typedb = TypeDBSource(connection, import_type)
    for stix_id in stix_id_list:
        obj = typedb.get(stix_id)
        obj_list.append(obj)

    return obj_list




def get_objects(obj, properties, embedded=[], sub_prop=[], import_type=import_type):
    """Interface for getting one or more STIX objects from TypeDB.

    Can be based on object tpe, with property constraints, embedded and sub-object constraints

    Args:
        - obj_typeql (string) - a valid Stx-ORM object that exists in the database
        - properties ([dict]) - a list of dicts providing comparisons between properties and constants
                                  - dict:
                                          - property-name - a TypeDB property
                                          - comparator - a two letter comparison
                                          - constant - a constant against which the property value is compared
        - embedded([stix-id]) - a list of valid stix-ids that exist in the database
        - sub_prop([dict]) - a list of valid stix-ids that exist in the database
                                  - dict:
                                          - sub-object typeql name
                                          - property-name - a TypeDB property
                                          - comparator - a two letter comparison
                                          - constant - a constant against which the property value is compared

    """
    id_list = []
    logger.debug("----------------------- Incoming Definition --------------------------------------")
    logger.debug(f"object is -> {obj}")
    for prop in properties:
        logger.debug(f"prop -> {prop}")
    logger.debug(f"embedded is -> {embedded}")
    for sub in sub_prop:
        logger.debug(f"sub_prop -> {sub}")
    match = _get_objects_tql(obj, properties, embedded, sub_prop, import_type)
    logger.debug("------------------- Resulting Match Statement ------------------------------------------")
    logger.debug(f"match is -> \n{match}")
    logger.debug("-------------------------------------------------------------")
    id_list = get_stix_ids(match)
    obj_list = get_list(id_list)
    return obj_list



def test_get_objects():
    # 0. Load the human_trigger.json file into typedb
    load_file(incident + "/human_trigger.json")
    # 1. Find incident created by identity
    # Return -> "incident--1a074418-9248-4a21-9918-a79d0f1dbc5b"
    obj = "incident"
    properties = []
    embedded = [
        "identity--2242662b-d581-4864-8696-fff719dc0500"
    ]
    sub_prop= []
    print("\n***** Test Incident - 1 ************")
    test_result  = get_objects(obj, properties, embedded, sub_prop, import_type)
    print(test_result)

    # 2. Find Email Address with Property  Equal to constant
    # Return -> "email-addr--9b7e29b3-fd8d-562e-b3f0-8fc8134f5dda"
    obj = "email-addr"
    properties = [{
        "prop_name": "value",
        "comparator" : "EQ",
        "prop_value": "admin@microsft.support.com"
    }]
    embedded = []    
    sub_prop= []
    print("\n***** Test Identity - 2 property equals ************")
    test_result  = get_objects(obj, properties, embedded, sub_prop, import_type)
    print(test_result)

    # 3. Find identity where Proeprty is Not Equal to Constant
    # Return -> { $stix-id "identity--1621d4d4-b67d-41e3-9670-f01faf20d111" isa stix-id; }
    #           { $stix-id "identity--2242662b-d581-4864-8696-fff719dc0500" isa stix-id; }
    #           { $stix-id "identity--987eeee1-413a-44ac-96cc-0a8acdcc2f2c" isa stix-id; }
    #           { $stix-id "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5" isa stix-id; }
    obj = "identity"
    properties = [{
        "prop_name": "identity_class",
        "comparator" : "NE",
        "prop_value": "individual"
    }]
    embedded = []    
    sub_prop= []
    print("\n***** Test Identity - 3 proeprty not equals ************")
    test_result  = get_objects(obj, properties, embedded, sub_prop, import_type)
    print(test_result)

    # 4. Find identity where both of two Property's EQ Constants
    # Return -> { $stix-id "identity--2242662b-d581-4864-8696-fff719dc0500" isa stix-id; }
    obj = "identity"
    properties = [{
        "prop_name": "identity_class",
        "comparator" : "EQ",
        "prop_value": "organization"
    },
    {
        "prop_name": "name",
        "comparator" : "EQ",
        "prop_value": "OS Threat"
    }]
    embedded = []    
    sub_prop= []
    print("\n***** identity Test -  two Property EQ ************")
    test_result  = get_objects(obj, properties, embedded, sub_prop, import_type)
    print(test_result)

    # 5. Find attack-pattern where one Ext Ref sub-object has a Property EQ Constant --> Mitre ATT&CK object
    # Return -> { $stix-id "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7" isa stix-id; }
    #           { $stix-id "attack-pattern--9db0cf3a-a3c9-4012-8268-123b9db6fd82" isa stix-id; }
    
    obj = "attack-pattern"
    sub_prop = [{
        "prop_name": "source_name",
        "comparator" : "EQ",
        "prop_value": "mitre-attack"
    }]
    embedded = []    
    properties = []
    print("\n***** Attack-Pattern Test - Ext Ref property EQ ************")
    test_result  = get_objects(obj, properties, embedded, sub_prop, import_type)
    print(test_result)


    # 6. Find impact where a property of an Extension equals a contant
    # Return -> { $stix-id "impact--1032f48b-28d1-451f-970e-78b736db8e13" isa stix-id; }
    obj = "impact"
    sub_prop = [{
        "prop_name": "information_type",
        "comparator" : "EQ",
        "prop_value": "credentials-user"
    }]
    embedded = []    
    properties = []
    print("\n***** impact Test - Extension proeprty equals ************")
    test_result  = get_objects(obj, properties, embedded, sub_prop, import_type)
    print(test_result)



def _get_objects_tql(obj, properties, embedded=[], sub_prop=[], import_type=import_type):
    """Function to return the typeQL for a Get Objects call.

    Can be based on object tpe, with property constraints, embedded and sub-object constraints

    Args:
        - obj_typeql (string) - a valid Stx-ORM object that exists in the database
        - properties ([dict]) - a list of dicts providing comparisons between properties 
                    with stix json property names (not typeql names) and constants
                                  - dict:
                                          - property-name - a TypeDB property
                                          - comparator - a two letter comparison
                                          - constant - a constant against which the property value is compared
        - embedded([stix-id]) - a list of valid stix-ids that exist in the database
        - sub_prop([dict]) - a list of valid stix-ids that exist in the database
                                  - dict:
                                          - sub-object typeql name
                                          - property-name - a TypeDB property
                                          - comparator - a two letter comparison
                                          - constant - a constant against which the property value is compared

    """
    auth = authorised_mappings(import_type)
    # object match statement
    obj_tql = auth["objects"][obj]
    obj_var = "$" + obj
    match = "match\n   " + obj_var + " isa " + obj +",\n         has stix-id $stix-id;\n"
    value = ""

    # object properties
    for prop in properties:
        prop_var = "$" + prop["prop_name"]
        match += "   " + obj_var + " has " + obj_tql[prop["prop_name"]] + " " + prop_var + ";\n"
        value += "   " + prop_var + compare[prop["comparator"]] + val_tql(prop["prop_value"]) + ";\n"

    # embedded properties
    for inc, embed in enumerate(embedded):
        prop_var = "$" + "Stix-Object" + str(inc)
        match += "   "  + prop_var + ' isa stix-core-object,\n' 
        match += "         "  + 'has stix-id "' + embed + '";\n'
        value += "   "  + "(owner:" +obj_var + ", pointed-to:" + prop_var +  ") isa embedded;\n"

    sub_obj_props = {}
    print(type(auth["sub_objects"]))
    for raw_key, raw_sub in auth["sub_objects"].items():
        for prop_key, prop_value in raw_sub.items():
            if prop_key not in sub_obj_props:
                sub_obj_props[prop_key] = prop_value

    # sub-object properties
    for inc, sub in enumerate(sub_prop):
         sub_var = "$Sub-Object" + str(inc) 
         prop_var = "$" + sub["prop_name"]
         prop_name = sub_obj_props[sub["prop_name"]]
         match +=  "   "  + sub_var + " isa stix-sub-object,\n"
         match +=  "         "  + "has " + prop_name + " " + prop_var + ";\n"
         match +=  "   "  + "(owner:" + obj_var + ", pointed-to:" + sub_var + ") isa embedded;\n"
         value +=  "   "  + prop_var + compare[sub["comparator"]] + val_tql(sub["prop_value"]) + ";\n"

    get = "   get $stix-id;\n"
    return match + value + get




##############################################################################

# if this file is run directly, then start here
if __name__ == '__main__':

    f1 = "aaa_attack_pattern.json"
    f2 = "aaa_identity.json"
    f3 = "aaa_indicator.json"
    f4 = "aaa_malware.json"
    f5 = "artifact_basic.json"
    f6 = "artifact_encrypted.json"
    f7 = "autonomous.json"
    f8 = "attack-campaign.json"
    f9 = "course_action.json"
    f10 = "directory.json"
    f11 = "domain.json"
    f12 = "email_basic_addr.json"
    f13 = "email_headers.json"
    f14 = "email_mime.json"
    f15 = "email_simple.json"
    f16 = "incident.json"
    f17 = 'file_archive_unencrypted.json'
    f18 = 'file_basic.json'
    f19 = 'file_basic_encoding.json'
    f20 = 'file_basic_parent.json'
    f21 = 'file_binary.json'
    f22 = 'file_image_simple.json'
    f23 = 'file_ntfs_stream.json'
    f24 = 'file_pdf_basic.json'
    f25 = 'grouping.json'
    f26 = 'note.json'
    f27 = 'process_ext_win_service.json'
    f28 = 'threat_actor.json'
    f29 = "observed.json"
    f30 = "x509_cert_v3_ext.json"
    file_list = [f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,f21,f22,f23,f24,f25]
    group_list = [f2, f3, f21, f25]
    note_list = [f2, f8, f26]

    data_path = "data/examples/"
    path1 = "test/data/standard/"
    path2 = "test/data/os-threat/test2/"
    path3 = "test/data/os-threat/incident_adjust/"
    path4 = "test/data/os-threat/test3/"
    cert_root = "data/stix_cert_data"
    cert1 = "/attack_pattern_sharing/"
    cert2 = "/campaign_sharing/"
    cert3 = "/confidence_sharing/"
    cert4 = "/course_of_action_sharing/"
    cert5 = "/data_marking_sharing/"
    cert6 = "/grouping_sharing/"
    cert7 = "/indicator_sharing/"
    cert8 = "/infrastructure_sharing/"
    cert9 = "/intrusion_set_sharing/"
    cert10 = "/location_sharing/"
    cert11 = "/malware_analysis_sharing/"
    cert12 = "/malware_sharing/"
    cert13 = "/note_sharing/"
    cert14 = "/observed_data_sharing/"
    cert15 = "/opinion_sharing/"
    cert16 = "/report_sharing/"
    cert17 = "/sighting_sharing/"
    cert18 = "/threat_actor_sharing/"
    cert19 = "/tool_sharing/"
    cert20 = "/versioning/"
    cert21 = "/vulnerability_sharing/"
    probs1 = "consumer_test/sighting_of_indicator.json"
    certs = [
        cert1, cert2, cert3, cert4, cert5, cert6, cert7, cert8, cert9, cert10, cert11, cert12, cert13,cert14,
        cert15, cert16, cert17, cert18, cert19, cert20, cert21
    ]

    file1 = "granular_markings.json"
    file2 = "attack_pattern_malware.json"
    file3 = "campaign_intrusion.json"
    file4 = "indicator-sighting.json"
    file5 = "malware_indicator.json"
    file6 = "marking_definitions.json"
    file7 = "report.json"
    file8 = "sighting_observable.json"
    file9 = "threat_actor.json"
    mitre_data = "data/mitre/traffic_duplication.json"

    mitre_raw = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
    mitre = "test/data/mitre/test/"
    mitre_test = "data/mitre/latest/"
    osthreat = "data/os-threat/"
    reports = "test/data/threat_reports/"
    poison = "poisonivy.json"
    incident = "test/data/os-threat/incident"
    incident_test = "test/data/os-threat/test"
    incident_adjust = "test/data/os-threat/incident_adjust"
    threattest = "history/"

    id_list = ['file--94ca-5967-8b3c-a906a51d87ac', 'file--5a27d487-c542-5f97-a131-a8866b477b46', 'email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265', 'email-message--cf9b4b7f-14c8-5955-8065-020e0316b559', 'intrusion-set--0c7e22ad-b099-4dc3-b0df-2ea3f49ae2e6', 'attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5', 'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74']
    # 019fde1c-
    id_list2 = ['file--94ca-5967-8b3c-a906a51d87ac']
    id_list3 = ['file--019fde1c-94ca-5967-8b3c-a906a51d87ac']
    stid1 = "task--7c5751c2-3c18-41bc-900c-685764c960f3"
    stid2 = "file--ec3415cc-5f4f-5ec8-bdb1-6f86996ae66d"
    stid3 = "sighting--300cd92e-d184-4c60-a97b-1759dc6780ed"
    #test_initialise()
    #load_file_list(path1, [f30, f21])
    #load_file(incident + "/human_trigger.json")
    #load_file(mitre + "attack_objects.json")
    #check_object(mitre + "attack_objects.json")
    #load_file(reports + poison)
    print("=====")
    print("=====")
    print("=====")
    #query_id(stid3)
    #check_dir_ids2(osthreat)
    #check_dir_ids(path1)
    check_dir(path1)
    #load_file(path1 + f24)
    #test_delete(data_path+file1)
    #test_get(stid1)
    #test_get_delete(incident)
    #test_initialise()
    #test_delete_dir(path1)
    #clean_db()
    #cert_test(cert_root+cert11)
    #cert_dict(cert_root, certs)
    #test_get_ids(connection, import_type)
    #test_ids_loaded(id_list2, ccls
    # onnection)
    #test_auth()
    #test_generate_docs()
    #backdoor_add(mitre + "attack_collection.json")
    #backdoor_add_dir(osthreat + threattest)
    #backdoor_add_dir(path1)
    #test_get_file(data_path + file1)
    #test_insert_statements(path2 + "evidence.json", stid3)
    #test_insert_statements(path1 + f29, stid2)
    #test_get_del_dir_statements(mitre)
    #test_json(osthreat + "feed.json")
    #test_feeds()
    #test_get_embedded("report--f2b63e80-b523-4747-a069-35c002c690db")
    #try_subgraph_get(reports + poison)
    #try_nodes_and_edges()
    #test_get_objects()
