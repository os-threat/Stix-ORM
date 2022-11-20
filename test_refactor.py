import json
import os
from stix.module.typedb import TypeDBSink, TypeDBSource
from stix.module.import_stix_to_typeql import stix2_to_typeql
from typedb.client import *
from stix2 import (v21, parse)
from stix.module.import_stix_to_typeql import raw_stix2_to_typeql, stix2_to_match_insert
from stix.module.delete_stix_to_typeql import delete_stix_object, add_delete_layers
from stix.module.initialise import check_stix_ids


import logging

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

import_type = {
    "STIX21": True,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK": False,
    "ATT&CK_Versions": ["12.0"],
    "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    "CACAO": False
}

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $ids isa stix-id;'


test_id = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
marking_id = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
file_id = 'file--364fe3e5-b1f4-5ba3-b951-ee5983b3538d'


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
    logger.debug(f' connection {connection}')
    typedb = TypeDBSink(connection, True, import_type)
    print(f'files {file_list}')
    for i, f in enumerate(file_list):
        logger.debug(f'i have entered the file loop, time {i}')
        if i > 100:
            break
        else:
            with open((path1+f), mode="r", encoding="utf-8") as df:
                print(f'I am about to load {f}')
                json_text = json.load(df)
                typedb.add(json_text)


def load_file(fullname):
    """ Add a json file to typeDB

    Args:
        fullname (): path and filename
    """
    logger.debug(f'inside load file {fullname}')
    with open(fullname, mode="r", encoding="utf-8") as f:
        json_text = json.load(f)
        typedb = TypeDBSink(connection, True, import_type)
        typedb.add(json_text)


def query_id(stixid):
    """  Print out the match/insert and match/delete statements for any stix-id

    Args:
        stixid ():
    """
    typedb = TypeDBSource(connection, import_type)
    stix_dict = typedb.get(stixid)
    stix_obj = parse(stix_dict)
    print(' ---------------------------Query Object----------------------')
    print(stix_obj.serialize(pretty=True))
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_obj, "STIX21")
    del_match, del_tql = delete_stix_object(stix_obj, dep_match, dep_insert, indep_ql, core_ql, "STIX21")
    print(' ---------------------------Delete Object----------------------')
    print(f'dep_match -> {dep_match}')
    print(f'dep_insert -> {dep_insert}')
    print(f'indep_ql -> {indep_ql}')
    print(f'core_ql -> {core_ql}')
    print("=========================== delete typeql below ====================================")
    print(f'del_match -> {del_match}')
    print(f'del_tql -> {del_tql}')


def get_stix_ids():
    """ Get all the stix-ids in a database, should be moved to typedb file

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
    file_list = []
    for i, s_file in enumerate(sorted_files):
        if os.path.isdir(os.path.join(dirpath, s_file)) or i<51:
            continue
        else:
            file_list.append(s_file)
            print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
            print(f'==================== {s_file} ===================================')
            with open(os.path.join(dirpath, s_file), mode="r", encoding="utf-8") as f:
                json_text = json.load(f)
                typedb_sink.add(json_text)
                #print(json.dumps(json_text, indent=4))
                print('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')

    stix_id_list = get_stix_ids()
    typedb_sink.delete(stix_id_list)
    #clean_db()
    print(f' files-> {file_list}')


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


def check_dir(dirpath):
    """ Open a directory and load all the files, optionally printing them

    Args:
        dirpath ():
    """
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
                typedb_sink.add(json_text)


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


def test_ids_loaded(id_list, connection):
    return_list = check_stix_ids(id_list, connection)
    print(f'return {return_list}')


# if this file is run directly, then start here
if __name__ == '__main__':

    f1 = "aaa_attack_pattern.json"
    f2 = "aaa_identity.json"
    f3 = "aaa_indicator.json"
    f4 = "aaa_malware.json"
    f5 = "artifact_basic.json"
    f6 = "artifact_encrypted.json"
    f7 = "autonomous.json"
    f8 = "campaign.json"
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
    file_list = [f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,f21,f22,f23,f24,f25]

    data_path = "data/examples/"
    path1 = "data/standard/"
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

    mitre = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-12.0.json"

    id_list = ['file--94ca-5967-8b3c-a906a51d87ac', 'file--5a27d487-c542-5f97-a131-a8866b477b46', 'email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265', 'email-message--cf9b4b7f-14c8-5955-8065-020e0316b559', 'intrusion-set--0c7e22ad-b099-4dc3-b0df-2ea3f49ae2e6', 'attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5', 'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74']
    # 019fde1c-
    id_list2 = ['file--94ca-5967-8b3c-a906a51d87ac']
    id_list3 = ['file--019fde1c-94ca-5967-8b3c-a906a51d87ac']
    #test_initialise()
    #load_file_list(path1, file_list)
    #load_file(data_path + file2)
    print("=====")
    print("=====")
    print("=====")
    #query_id(test_id)
    #check_dir(path1)
    #test_delete(path1+files10)
    #test_initialise()
    #test_delete_dir(path1)
    #clean_db()
    #cert_test(cert_root+cert11)
    cert_dict(cert_root, certs)
    #test_get_ids(connection, import_type)
    #test_ids_loaded(id_list2, connection)