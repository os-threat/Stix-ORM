import json
import types
import datetime
import re
from typing import Optional, Dict

from stix2 import *
from stix2.v21 import *
from stix2.utils import is_object, is_stix_type, get_type_from_id, is_sdo, is_sco, is_sro
from stix.module.definitions.stix21 import stix_models
from stix.module.definitions.attack import attack_models
from stix.module.definitions.os_threat import os_threat_models
from stix.module.definitions.cacao import cacao_models
from stix.module.definitions.kestrel import kestrel_models

import logging

#logger = logging.getLogger(__name__)


##############################################################
#  1.) Default Import Type at only Stix Objects, all else False
############################################################


default_import_type = {
    "STIX21": True,
    "ATT&CK": False,
    "os-intel": False,
    "os-hunt": False,
    "kestrel": False,
    "CACAO": False,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK_Versions": ["12.1"],
    "ATT&CK_Domains": ["Enterprise ATT&CK", "Mobile ATT&CK", "ICS ATT&CK"]
}


##############################################################
#  2.) References used to Categorise Choices and Shapes for all Objects
############################################################
process_maps = [{
    "name": "reln_name",
    "keys": ["embedded_relations", "standard_relations", "list_of_objects", "key_value_relations", "extension_relations", "relations_sro_roles"],
    "match":["relations_embedded", "relations_sro_roles", "relations_list_of_objects", "relations_key_value", "relations_extensions_and_objects", "relations_sro_roles"],
    "cond": ["rel", "stix", "name", "name", "stix", "stix"]
},{
    "name": "reln",
    "keys": ["embedded_relations", "standard_relations", "list_of_objects", "key_value_relations", "extension_relations", "relations_sro_roles"],
    "match":["relations_embedded", "relations_sro_roles", "relations_list_of_objects", "relations_key_value", "relations_extensions_and_objects", "relations_sro_roles"],
    "cond": []
}, {
    "name": "tql_types",
    "keys": ["sdo", "sro", "sco", "sub", "meta"],
    "match":["object_conversion", "object_conversion", "object_conversion", "object_conversion", "object_conversion"],
    "cond": ["sdo", "sro", "sco", "sub", "meta" ]
}, {
    "name": "is_lists",
    "keys": ["sdo", "sro", "sco", "sub"],
    "match":["is_list_sdo", "is_list_sro", "is_list_sco", "is_list_sub_objects"],
    "cond": ["sdo", "sro", "sco", "sub"]
}, {
    "name": "direct",
    "keys": ["sub_objects", "objects"],
    "match":["sub_objects", "data"],
    "cond": []
}, {
    "name": "conv",
    "keys": ["sdo", "sro", "sco", "sub"],
    "match":["object", "object", "object", "object"],
    "cond": ["sdo", "sro", "sco", "sub"]
}, {
    "name": "classes",
    "keys": ["sdo", "sro", "sco", "sub"],
    "match":["object", "object", "object", "object"],
    "cond": ["sdo", "sro", "sco", "sub"]
}]

domains = {
    "stix": stix_models,
    "attack": attack_models,
    "os-threat": os_threat_models,
    "cacao": cacao_models,
    "kestrel": kestrel_models
}


def authorised_mappings(import_type=default_import_type):
    auth = {}
    auth["reln_name"] = {}
    auth["reln"] = {}
    auth["tql_types"] = {}
    auth["is_lists"] = {}

    # setup Stix by default
    auth_domains = [domains["stix"]]
    # setup "ATT&CK" if selected
    if import_type["ATT&CK"]:
        auth_domains.append(domains["attack"])
    # setup "os-threat" if selected
    if import_type["os-intel"] or import_type["os-hunt"]:
        auth_domains.append(domains["os-threat"])
    # setup "CACAO" if selected
    if import_type["CACAO"]:
        auth_domains.append(domains["cacao"])
    # setup "kestrel" if selected
    if import_type["kestrel"]:
        auth_domains.append(domains["kestrel"])


    dom=["stix","attack","os-threat", "cacao"]
    # initialise authorisation object, for documentation purposes
    auth["reln_name"]["embedded_relations"] = []
    auth["reln_name"]["standard_relations"] = []
    auth["reln_name"]["list_of_objects"] = []
    auth["reln_name"]["key_value_relations"] = []
    auth["reln_name"]["extension_relations"] = []
    auth["reln_name"]["relations_sro_roles"] = []
    auth["reln"]["embedded_relations"] = []
    auth["reln"]["standard_relations"] = []
    auth["reln"]["list_of_objects"] = []
    auth["reln"]["key_value_relations"] = []
    auth["reln"]["extension_relations"] = []
    auth["reln"]["relations_sro_roles"] = []
    auth["tql_types"]["sdo"] = []
    auth["tql_types"]["sro"] = []
    auth["tql_types"]["sco"] = []
    auth["tql_types"]["sub"] = []
    auth["tql_types"]["meta"] = []
    auth["is_lists"]["sdo"] = {}
    auth["is_lists"]["sro"] = {}
    auth["is_lists"]["sco"] = {}
    auth["is_lists"]["sub"] = {}
    auth["sub_objects"] = {}
    auth["objects"] = {}
    auth["conv"] = {}
    auth["conv"]["sdo"] = []
    auth["conv"]["sro"] = []
    auth["conv"]["sco"] = []
    auth["conv"]["sub"] = []
    auth["classes"] = {}
    auth["classes"]["sdo"] = {}
    auth["classes"]["sro"] = {}
    auth["classes"]["sco"] = {}
    auth["classes"]["sub"] = {}

    for j, domain in enumerate(auth_domains):
        for process in process_maps:
            name = process["name"]
            keys = process["keys"]
            matches = process["match"]
            conds = process["cond"]
            if name == "reln_name":
                #logger.debug("----------- reln_name ------------")
                for i, key in enumerate(keys):
                    if domain["mappings"].get(matches[i], False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_list = [x[conds[i]] for x in domain["mappings"][matches[i]]]
                        auth[name][key].extend(value_list)
            elif name == "reln":
                #logger.debug("--------- reln--------------")
                for i, key in enumerate(keys):
                    if domain["mappings"].get(matches[i], False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{key}, match->{matches[i]}')
                        value_list = domain["mappings"][matches[i]]
                        auth[name][key].extend(value_list)
            elif name == "tql_types":
                #logger.debug("---------- tql_types -------------")
                for i, key in enumerate(keys):
                    if domain["mappings"].get("object_conversion", False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_list = [x["type"] for x in domain["mappings"][matches[i]] if x["object"] == conds[i]]
                        auth[name][key].extend(value_list)
            elif name == "is_lists":
                #logger.debug("--------- is_lists --------------")
                for i, key in enumerate(keys):
                    if domain["mappings"].get(matches[i], False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_dict = domain["mappings"][matches[i]]
                        auth[name][key].update(value_dict)
            elif name == "direct":
                #logger.debug("-------- direct ---------------")
                for i, key in enumerate(keys):
                    if domain.get(matches[i], False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}')
                        value_dict = domain[matches[i]]
                        auth[key].update(value_dict)
            elif name == "conv":
                #logger.debug("-------- conv ---------------")
                for i, key in enumerate(keys):
                    if domain["mappings"].get("object_conversion", False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_list = [x for x in domain["mappings"]["object_conversion"] if x["object"] == conds[i]]
                        auth[name][key].extend(value_list)
            elif name == "classes":
                #logger.debug("-------- conv ---------------")
                for i, key in enumerate(keys):
                    if domain["classes"].get(key, False):
                        #logger.debug(f'Auth Loading: domain->{dom[j]}, name->{name}, key->{keys[i]}, match->{matches[i]}, cond->{conds[i]}')
                        value_dict = domain["classes"][key]
                        auth[name][key].update(value_dict)

            else:
                pass

    # finally add the import type to the auth object
    auth.update(import_type)

    return auth

