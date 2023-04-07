import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource, get_embedded_match
from typedb.client import *
from stix.module.orm.import_objects import raw_stix2_to_typeql
from stix.module.orm.delete_object import delete_stix_object
from stix.module.orm.export_object import convert_ans_to_stix
from stix.module.authorise import authorised_mappings, import_type_factory
from stix.module.parsing.parse_objects import parse
from stix.module.generate_docs import configure_overview_table_docs, object_tables
from stix.module.initialise import sort_layers, load_typeql_data

import logging

from stix.module.typedb_lib.import_type_factory import AttackDomains, AttackVersions

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
#logger.addHandler(logging.StreamHandler())


# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type = import_type_factory.get_attack_import()

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $ids isa stix-id;'


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
        with TypeDB.core_client(g_uri) as client:
            with client.session(connection["database"], SessionType.DATA) as session:
                with session.transaction(TransactionType.READ) as read_transaction:
                    answer_iterator = read_transaction.query().match(match)
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
    #logger.debug(f' i have parsed\n')
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, import_type)
    #logger.debug(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
    dep_obj["dep_match"] = dep_match
    dep_obj["dep_insert"] = dep_insert
    dep_obj["indep_ql"] = indep_ql
    dep_obj["core_ql"] = core_ql
    return dep_obj


def test_insert_statements(pahhway, stid):
    with open(pahhway, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
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
    typedb = TypeDBSink(connection, True, import_type)
    layers = []
    indexes = []
    missing = []
    cyclical = []
    type_ql_list = []
    id_list = []
    obj_list = []
    dirFiles = os.listdir(dirpath)
    sorted_files = sorted(dirFiles)
    logger.debug(sorted_files)
    typedb_sink = TypeDBSink(connection, True, import_type)
    typedb_source = TypeDBSource(connection, import_type)
    for s_file in sorted_files:
        if os.path.isdir(os.path.join(dirpath, s_file)):
            continue
        else:
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                for element in json_text:
                    logger.debug(f'**********==={element}')
                    obj_list.append(element)
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)

                    dep_obj = dict_to_typeql(element, import_type)
                    # logger.debug('----------------------------------------------------------------------------------------------------')
                    # logger.debug(f'\ndep_match {dep_obj["dep_match"]} \ndep_insert {dep_obj["dep_insert"]} \nindep_ql {dep_obj["indep_ql"]} \ncore_ql {dep_obj["core_ql"]}')
                    # logger.debug('----------------------------------------------------------------------------------------------------')
                    layers, indexes, missing, cyclical = update_layers(layers, indexes, missing, dep_obj, cyclical)

    logger.debug(f'missing {missing}, cyclical {cyclical}')
    newlist = []
    duplist = []
    if missing == [] and cyclical == []:
        # add the layers into a list of strings
        for layer in layers:
            stid = layer["id"]
            if stid not in newlist:
                newlist.append(stid)
                dep_match = layer["dep_match"]
                dep_insert = layer["dep_insert"]
                indep_ql = layer["indep_ql"]
                core_ql = layer["core_ql"]
                #print(f'\ndep_match {dep_match} \ndep_insert {dep_insert} \nindep_ql {indep_ql} \ncore_ql {core_ql}')
                prestring = ""
                if dep_match != "":
                    prestring = "match " + dep_match
                upload_string = prestring + " insert " + indep_ql + dep_insert
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
    print(f'\n\n\n===========================\nduplist -> {duplist}')
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


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
    typedb = TypeDBSink(connection, True, import_type)


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
                #print(f'I am about to load {f}')
                json_text = json.load(df)
                obj_list.extend(json_text)

    typedb.add(obj_list)


def load_file(fullname):
    """ Add a json file to typeDB

    Args:
        fullname (): path and filename
    """
    logger.debug(f'inside load file {fullname}')
    input_id_list=[]
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb = TypeDBSink(connection, True, import_type)
        for stix_dict in json_text:
            input_id_list.append(stix_dict.get("id", False))
        typedb.add(json_text)
    id_set = set(input_id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


def check_object(fullname):
    logger.debug(f'inside load file {fullname}')
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
    print("\n\n=============\n-------------\n$$$$$$$$$$$$$$$$$$$$$\n")
    for obj_id in id_list:
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
    print(' ---------------------------Delete Object----------------------')
    print(f'dep_match -> {dep_match}')
    print(f'dep_insert -> {dep_insert}')
    print(f'indep_ql -> {indep_ql}')
    print(f'core_ql -> {core_ql}')
    print("=========================== delete typeql below ====================================")
    del_match, del_tql = delete_stix_object(stix_obj, dep_match, dep_insert, indep_ql, core_ql, import_type)
    print(f'del_match -> {del_match}')
    print(f'del_tql -> {del_tql}')


def get_stix_ids():
    """ Get all the stix-ids in a database, should be moved to typedb_lib file

    Returns:
        id_list : list of the stix-ids in the database
    """
    g_uri = connection["uri"] + ':' + connection["port"]
    id_list = []
    with TypeDB.core_client(g_uri) as client:
        with client.session(connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as read_transaction:
                answer_iterator = read_transaction.query().match(get_ids)
                ids = [ans.get("ids") for ans in answer_iterator]
                for sid_obj in ids:
                    sid = sid_obj.get_value()
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
    typedb = TypeDBSink(connection, False, import_type)
    typedb.delete(local_list)


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
    #typedb_sink.delete(stix_id_list)
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
    """ Open a directory and load all the files,
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
    """ Open a directory and load all the files,
    creating a list of objects first and then adding them to the db

    Args:
        dirpath ():
    """
    id_list = []
    obj_list = []
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
                    obj_list.append(element)
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
    typedb_sink.add(obj_list)
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


def check_dir(dirpath):
    """ Open a directory and load all the files, optionally printing them

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
                for element in f:
                    temp_id = element.get('id', False)
                    if temp_id:
                        id_list.append(temp_id)
                json_text = json.load(f)
                typedb_sink.add(json_text)
    id_set = set(id_list)
    id_typedb = set(get_stix_ids())
    len_files = len(id_set)
    len_typedb = len(id_typedb)
    id_diff = id_set - id_typedb
    print(f'\n\n\n===========================\ninput len -> {len_files}, typedn len ->{len_typedb}')
    print(f'difference -> {id_diff}')


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
    file_list = [f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,f21,f22,f23,f24,f25]
    group_list = [f2, f3, f21, f25]
    note_list = [f2, f8, f26]

    data_path = "data/examples/"
    path1 = "data/standard/"
    path2 = "data/mitre/load/"
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
    mitre_data = "data/mitre/enterprise-attack.json"

    mitre_raw = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
    mitre = "data/mitre/"

    id_list = ['file--94ca-5967-8b3c-a906a51d87ac', 'file--5a27d487-c542-5f97-a131-a8866b477b46', 'email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265', 'email-message--cf9b4b7f-14c8-5955-8065-020e0316b559', 'intrusion-set--0c7e22ad-b099-4dc3-b0df-2ea3f49ae2e6', 'attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5', 'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74']
    # 019fde1c-
    id_list2 = ['file--94ca-5967-8b3c-a906a51d87ac']
    id_list3 = ['file--019fde1c-94ca-5967-8b3c-a906a51d87ac']
    stid1 = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    stid2 = "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
    stid3 = "ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8"
    #test_initialise()
    #load_file_list(path1, [f2, f29])
    #load_file(path1 + f29)
    #load_file(mitre + "test.json")
    #check_object(mitre + "test.json")
    #load_file(data_path + file1)
    print("=====")
    print("=====")
    print("=====")
    #query_id(stid1)
    #check_dir_ids2(path1)
    #check_dir_ids(path1)
    #check_dir(path1)
    #test_delete(data_path+file1)
    #test_get(stid1)
    test_get_delete(path2 + "test.json")
    #test_initialise()
    #test_delete_dir(path1)
    #clean_db()
    #cert_test(cert_root+cert11)
    #cert_dict(cert_root, certs)
    #test_get_ids(connection, import_type)
    #test_ids_loaded(id_list2, connection)
    #test_auth()
    #test_generate_docs()
    #backdoor_add(mitre + "test.json")
    #backdoor_add_dir(path2)
    #test_get_file(data_path + file1)
    #test_insert_statements(mitre + "test.json", stid1)
    #test_insert_statements(path1 + f29, stid2)
    #test_get_del_dir_statements(path1)
