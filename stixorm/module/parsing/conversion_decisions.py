from typing import Dict, List, Union
import copy

from stixorm.module.authorise import  import_type_factory

import logging

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType
from stixorm.module.typedb_lib.model.definitions import DefinitionName
from stixorm.module.parsing.content.parse import determine_content_object_from_list_by_tests, get_tqlname_from_type_and_protocol
from stixorm.module.parsing.content.parse import ParseContent

logger = logging.getLogger(__name__)
all_imports = import_type_factory.get_all_imports()



attack_model = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK)
stix_model = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
os_threat_model = get_definition_factory_instance().lookup_definition(DefinitionName.OS_THREAT)
oca_model = get_definition_factory_instance().lookup_definition(DefinitionName.OCA)
mbc_model = get_definition_factory_instance().lookup_definition(DefinitionName.MBC)
flow_model = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK_FLOW)


def stix_dict_to_tql(stix_dict) -> Union[dict, str, List[str], str]:
    """ convert Stix object into a data model for processing

    Args:
        stix_dict (): a dict with guaranteed base-level Stix properties

    Returns:
        obj_tql: {} - the dict of the tql properties
        tql_name: str - the typeql name of the object
        is_list: [] - a list of all the properties that are lists
        protocol: str - the protocol of the object, e.g. stix21, attack, os-threat, oca, mbc, attack_flow

    """
    # 1. Establish variables
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(all_imports)
    obj_tql = {}
    is_list =[]
    protocol = ""
    tql_name = ""
    # 2. get content record
    content_record: ParseContent = determine_content_object_from_list_by_tests(stix_dict=stix_dict, content_type="class")
    # 3. get twl name from content
    tql_name = content_record.typeql
    # 4. get protocol from content
    protocol = content_record.protocol
    # 5. Get stix type
    stix_type = content_record.stix_type
    # Get group from content
    group = content_record.group
    # IF group equals meta then grp = sdo
    grp = group
    base = "base_sdo"
    if group == "meta":
        grp = "sdo"
    elif group == "sro":
        base = "base_sro"
    elif group == "sco":
        base = "base_sco"

    # 6. Based on protocol type, choose is list and obj tql
    match protocol:
        case "stix21":
            obj_tql = copy.deepcopy(stix_model.get_data(tql_name))
            is_list.extend(auth["is_lists"][group][tql_name])
        case "attack":
            obj_tql.update(copy.deepcopy(attack_model.get_data(tql_name)))
            obj_tql.update(copy.deepcopy(attack_model.get_base("attack_base")))
            is_list.extend(auth["is_lists"][group][tql_name])
            is_list.extend(auth["is_lists"][group]["attack"])
        case "os-threat":
            obj_tql = copy.deepcopy(os_threat_model.get_data(tql_name))
            is_list.extend(auth["is_lists"][group][tql_name])
        case "oca":
            obj_tql = copy.deepcopy(oca_model.get_data(tql_name))
            is_list.extend(auth["is_lists"][group][tql_name])
        case "mbc":
            obj_tql = copy.deepcopy(mbc_model.get_data(tql_name))
            is_list.extend(auth["is_lists"][group][tql_name])
        case "flow":
            obj_tql = copy.deepcopy(flow_model.get_data(tql_name))
            is_list.extend(auth["is_lists"][group][tql_name])

    # 7. Add on the underlying base SDO properties
    obj_tql.update(stix_model.get_base(base))
    is_list.extend(auth["is_lists"][grp][grp])
    logger.debug("in sdo decisions")
    logger.debug(f'obj tql {obj_tql}')

    return obj_tql, tql_name, is_list, protocol

####################################################################################################
#
# Import conversion decisions for embedded objects (foreign keys)
#
####################################################################################################

def get_tqlname_from_content_by_ID(stid: str, protocol="") -> str:
    """
        Get the typeql name of the stix object from the content by ID
    Args:
        stid (): the stix id
        all_imports (): all imports
        protocol (): the protocol to use

    Returns:
        source: the typeql source of the object
    """
    stix_type = stid.split('--')[0]
    return get_tqlname_from_type_and_protocol(stix_type, protocol)


def get_embedded_match(source_id: str, all_imports: ImportType, i=0, protocol=""):
    """
        Assemble the typeql variable and match statement given the stix-id, and the increment
    Args:
        source_id (): stix-id to use
        i (): number of times this type of object has been used

    Returns:
        source_var, the typeql string of the variable
        match, the typeql match statement
    """
    source_type = get_tqlname_from_content_by_ID(source_id, protocol)
    source_var = '$' + source_type + str(i)
    if source_type == 'relationship' or source_type == "attack-relation":
        source_type = 'stix-core-relationship'
    match = f' {source_var} isa {source_type}, has stix-id "{source_id}";\n'
    return source_var, match


def get_full_object_match(source_id: str, all_imports: ImportType, protocol: str):
    """
        Return a typeql match statement for this stix object
    Args:
        source_id (): the stix-id to look for

    Returns:
        source_var, the typeql string of the variable
        match, the typeql match statement
    """
    source_var, match = get_embedded_match(source_id, all_imports, 0, protocol)
    match += source_var + ' has $properties;\n'
    # match += '$embedded (owner:' + source_var + ', pointed-to:$point ) isa embedded;\n'
    return source_var, match
