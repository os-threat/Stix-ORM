import json

from stix.module.definitions.stix21 import stix_models
from stix.module.authorise import authorised_mappings, import_type_factory
import logging

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# logger.addHandler(logging.StreamHandler())

import_type = import_type_factory.get_all_imports()

# file name keys used to work with the data/parsertrees folder
simple_keys = [
    "state_1",
    "state_2",
    "state_3",
    "state_4",
    "state_5",
    "state_6",
    "state_7"
]
all_keys = [
    "state_1",
    "state_2",
    "state_3",
    "state_4",
    "state_5",
    "state_6",
    "state_7",
    "state_8",
    "state_9",
    "state_10",
    "state_11",
    "state_12"
]

embedded = {
    "artifact": {"created_by_ref": ["identity"]},
    "autonomous-system": {"created_by_ref": ["identity"]},
    "directory": {"created_by_ref": ["identity"], "contains_refs": ["directory"]},
    "domain-name": {"created_by_ref": ["identity"], "resolves_to_refs": ["domain-name", "ipv4-addr", "ipv6-addr"]},
    "email-addr": {"created_by_ref": ["identity"], "belongs_to_refs": ["user-account"]},
    "email-message": {"created_by_ref": ["identity"], "from_ref": ["email-addr"], "to_refs": ["email-addr"],
                      "cc_refs": ["email-addr"], "bcc_refs": ["email-addr"], "raw_email_ref": ["artifact"],
                      "sender_ref": ["email-addr"]},
    "email-mime-part-type": {"body_raw_ref": ["Artifact", "file"]},
    "file": {"created_by_ref": ["identity"], "parent_directory_ref": ["directory"], "content_ref": ["artifact"],
             "contains_refs": ["file", "ipv4-addr", "ipv6-addr", "url", "domain-name", "email-addr", "email-message",
                               "email-mime-part-type", "windows-registry-key", "x509-certificate", "mutex",
                               "network-traffic", "process", "software", "windows-service", "user-account",
                               "windows-registry-value-type", "windows-registry-key", "windows-registry-value-type"]},
    "archive-ext": {"contains_refs": ["file", "directory"]},
    "ipv4-addr": {"created_by_ref": ["identity"], "resolves_to_refs": ["mac-addr"],
                  "belongs_to_refs": ["autonomous-system"]},
    "ipv6-addr": {"created_by_ref": ["identity"], "resolves_to_refs": ["mac-addr"],
                  "belongs_to_refs": ["autonomous-system"]},
    "mac-addr": {"created_by_ref": ["identity"]},
    "mutex": {"created_by_ref": ["identity"]},
    "network-traffic": {"created_by_ref": ["identity"],
                        "src_ref": ["ipv4-addr", "ipv6-addr", "mac-addr", "domain-name"],
                        "dst_ref": ["ipv4-addr", "ipv6-addr", "mac-addr", "domain-name"],
                        "src_payload_ref": ["artifact"], "dst_payload_ref": ["artifact"],
                        "encapsulates_refs": ["network-traffic"], "encapsulated_by_ref": ["network-traffic"]},
    "http-request-ext": {"message_body_data_ref": ["artifact"]},
    "process": {"created_by_ref": ["identity"], "opened_connection_refs ": ["network-traffic"],
                "creator_user_ref": ["user-account"], "image_ref": ["file"], "parent_ref": ["process"],
                "child_refs": ["process"]},
    "windows-service-ext": {"service_dll_refs": ["file"]},
    "software": {"created_by_ref": ["identity"]},
    "url": {"created_by_ref": ["identity"]},
    "user-account": {"created_by_ref": ["identity"]},
    "windows-registry-key": {"created_by_ref": ["identity"], "creator_user_ref": ["user-account"]},
    "x509-certificate": {"created_by_ref": ["identity"], }
}


def get_embedded_properties(data):
    properties = set()

    for value in data.values():
        if isinstance(value, dict):
            for nested_value in value.values():
                if isinstance(nested_value, dict):
                    properties.update(nested_value.keys())

    return properties


def make_examples():
    """
    open the example files and send them to the tql processing
    """
    for key in simple_keys:
        with open("data/parsetrees/" + key + ".json", 'r') as file:
            pattern_obj = json.load(file)
            tql_match = pattern_to_tql(pattern_obj)

        with open("data/parsetrees/" + key + ".txt", 'r') as file:
            statement = file.read()
        print("=====================================================================")
        print(statement)
        print("---------------------------------------------------------------------")
        print(tql_match)


def pattern_to_tql(stix_pattern):
    """

    Args:
        stix_pattern (): the returned object from the Antlr parser

    Returns:
        tql_match: the match tql statement

    """
    auth = authorised_mappings(import_type)
    inc = 0
    tql_match = ""
    for k, v in stix_pattern.items():
        if k == "expression":
            tql_match += expression(inc, v, auth)
        elif k == "observation":
            tql_match += observation(inc, v, auth)
        else:
            logger.debug("Unknown key: " + k)

    tql_match = "match " + tql_match
    return tql_match


def expression(inc, comp_obj, auth):
    pass


def observation(inc, comp_obj, auth):
    """
    Function to setup the observation part of the tql statement
    Args:
        inc (): current increment
        comp_obj (): the obeservation object from the stix-pattern

    Returns:
        tql_match: the match tql statement

    """
    tql_match = ""
    obj_list = comp_obj["objects"]
    join = comp_obj["join"]
    qualifiers = comp_obj["qualifiers"]
    expressions = comp_obj["expressions"]
    list_len = len(expressions)

    # handle error condition
    if list_len > 1 and join == "null":
        raise Exception("Join is null but there are multiple expressions")

    for count, express in enumerate(expressions):
        for k, v in express.items():
            if k == "comparison":
                tql_match += comparison(inc, v, auth)
                if count < list_len - 2 and join is not None:
                    tql_match += " " + join + " "
            else:
                raise Exception("Unknown Observation key: " + k)

    if qualifiers is not None:
        tql_match += qualify(qualifiers)
    return tql_match, inc


def comparison(inc, v, auth):
    """
    function to manage the comparison part of the tql statement
    Args:
        inc (): current increment
        v (): the comparison object from the stix-pattern

    Returns:
        tql_match: the match tql statement

    """
    tql_match = ""
    sco_type = v["object"]
    path_list = v["path"]
    path_length = len(path_list)
    negated = v["negated"]
    operator = v["operator"]
    value = v["value"]

    base = {}
    base = stix_models["base"]["base_sco"]
    base.update(auth["objects"][sco_type])
    var_name = "$" + sco_type + str(inc)
    tql_match += var_name + " isa " + sco_type

    for count, property in enumerate(path_list):
        if property[0:1] == "[":
            # handle list
            pass


    return tql_match

def qualify(qualifiers):
    """
    function to manage the qualifiers part of the tql statement
    Args:
        qualifiers (): the qualifiers object from the stix-pattern

    Returns:
        tql_match: the match tql statement

    """
    tql_match = ""
    for qualifier in qualifiers:
        for k, v in qualifiers.items():
            if k == "repeats":
                tql_match += "start " + v + " "
            elif k == "within":
                tql_match += "within " + v + " "
            else:
                raise Exception("Unknown Qualifiers key: " + k)
    return tql_match


quali = [
    {
        "repeats": {
            "value": 5
        }
    },
    {
        "within": {
            "value": 180,
            "unit": "SECONDS"
        }
    }
]


def comparison(inc, comp_obj):
    """
    function to manage the comparison operation inside a stix-pttern
    and return a tql statement to extract the comparison
    """
    local_obj = comp_obj["object"]
    path_list = comp_obj["path"]
    negated = comp_obj["negated"]
    operator = comp_obj["operator"]
    value = comp_obj["value"]
    objvar = "$" + local_obj + str(inc)

    inc += 1
