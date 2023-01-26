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

import logging

logger = logging.getLogger(__name__)

default_import_type = {
    "STIX21": True,
    "os-intel": False,
    "os-hunt": False,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK": False,
    "ATT&CK_Versions": ["12.0"],
    "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    "CACAO": False
}


##############################################################
#  1.) Methods to Add 2_tql() Capability to all Stix Objects
############################################################


def authorised_mappings(import_type=None):
    auth = {}
    auth["reln_name"] = {}
    auth["reln"] = {}
    auth["tql_types"] = {}
    auth["is_lists"] = {}

    if import_type is None:
        import_type = default_import_type

    # stix baselines
    if import_type["STIX21"]:
        auth["reln_name"]["embedded_relations"] = [x["rel"] for x in stix_models["mappings"]["relations_embedded"]]
        auth["reln_name"]["standard_relations"] = [x["stix"] for x in stix_models["mappings"]["relations_sro_roles"]]
        auth["reln_name"]["list_of_objects"] = [x["name"] for x in stix_models["mappings"]["relations_list_of_objects"]]
        auth["reln_name"]["key_value_relations"] = [x["name"] for x in stix_models["mappings"]["relations_key_value"]]
        auth["reln_name"]["extension_relations"] = [x["stix"] for x in stix_models["mappings"]["relations_extensions_and_objects"]]
        auth["reln"]["embedded_relations"] = stix_models["mappings"]["relations_embedded"]
        auth["reln"]["standard_relations"] = stix_models["mappings"]["relations_sro_roles"]
        auth["reln"]["list_of_objects"] = stix_models["mappings"]["relations_list_of_objects"]
        auth["reln"]["key_value_relations"] = stix_models["mappings"]["relations_key_value"]
        auth["reln"]["extension_relations"] = stix_models["mappings"]["relations_extensions_and_objects"]
        auth["reln"]["relations_sro_roles"] = stix_models["mappings"]["relations_sro_roles"]
        auth["tql_types"]["sdo"] = stix_models["mappings"]["types_sdo"]
        auth["tql_types"]["sro"] = stix_models["mappings"]["types_sro"]
        auth["tql_types"]["sco"] = stix_models["mappings"]["types_sco"]
        auth["tql_types"]["meta"] = stix_models["mappings"]["types_meta"]
        auth["is_lists"]["sdo"] = stix_models["mappings"]["is_list_sdo"]
        auth["is_lists"]["sro"] = stix_models["mappings"]["is_list_sro"]
        auth["is_lists"]["sco"] = stix_models["mappings"]["is_list_sco"]
        auth["is_lists"]["sub"] = stix_models["mappings"]["is_list_sub_objects"]
        auth["sub_objects"] = stix_models["sub_objects"]
        auth["objects"] = stix_models["data"]

    #
    if import_type["ATT&CK"]:
        auth["reln_name"]["embedded_relations"].extend([x["typeql"] for x in attack_models["mappings"]["relations_embedded"]])
        auth["reln_name"]["standard_relations"].extend([x["typeql"] for x in attack_models["mappings"]["relations_sro_roles"]])
        auth["reln_name"]["list_of_objects"].extend([x["typeql"] for x in attack_models["mappings"]["relations_list_of_objects"]])
        auth["reln_name"]["key_value_relations"].extend([x["typeql"] for x in attack_models["mappings"]["relations_key_value"]])
        auth["reln_name"]["extension_relations"].extend([x["relation"] for x in attack_models["mappings"]["relations_extensions_and_objects"]])
        auth["reln"]["embedded_relations"].extend(attack_models["mappings"]["relations_embedded"])
        auth["reln"]["standard_relations"].extend(attack_models["mappings"]["relations_sro_roles"])
        auth["reln"]["list_of_objects"].extend(attack_models["mappings"]["relations_list_of_objects"])
        auth["reln"]["key_value_relations"].extend(attack_models["mappings"]["relations_key_value"])
        auth["reln"]["extension_relations"].extend(attack_models["mappings"]["relations_extensions_and_objects"])
        auth["reln"]["relations_sro_roles"].extend(attack_models["mappings"]["relations_sro_roles"])
        auth["tql_types"]["sdo"].extend(attack_models["mappings"]["types_sdo"])
        auth["tql_types"]["sro"].extend(attack_models["mappings"]["types_sro"])
        auth["tql_types"]["sco"].extend(attack_models["mappings"]["types_sco"])
        auth["tql_types"]["meta"].extend(attack_models["mappings"]["types_meta"])
        auth["is_lists"]["sdo"].update(attack_models["mappings"]["is_list_sdo"])
        auth["is_lists"]["sro"].update(attack_models["mappings"]["is_list_sro"])
        auth["is_lists"]["sco"].update(attack_models["mappings"]["is_list_sco"])
        auth["is_lists"]["sub"].update(attack_models["mappings"]["is_list_sub_objects"])
        auth["sub_objects"].update(attack_models["sub_objects"])
        auth["objects"].update(attack_models["data"])
    # if os-threat, implement here

    # finally add the import type to the auth object
    auth.update(import_type)

    return auth

