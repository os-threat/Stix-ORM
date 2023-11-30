from typing import Dict, List
import copy

from stixorm.module.authorise import  import_type_factory

import logging

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType
from stixorm.module.typedb_lib.model.definitions import DefinitionName

logger = logging.getLogger(__name__)
default_import_type = import_type_factory.get_default_import()



attack_model = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK)
stix_model = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
os_threat_model = get_definition_factory_instance().lookup_definition(DefinitionName.OS_THREAT)


def sdo_type_to_tql(sdo_type: str,
                    import_type:ImportType=default_import_type,
                    attack_object=False, subtechnique=False, step_type="") -> [dict, str, dict, str]:
    """ convert Stix object into a data model for processing

    Args:
        sdo_type (): the Stix2 SDO type
        import_type (): the type of import to use

    Returns:
        obj_tql : the dict of the tql properties
        tql_name : the typeql name of the object
        is_list: a list of all the porperties that are lists

    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    obj_tql = {}
    is_list =[]
    protocol = ""
    tql_name = sdo_type
    logger.debug("in sdo decisions")
    logger.debug(f'obj tql {obj_tql}')
    logger.debug(f"variables, stix {auth['STIX21']}, attack is {auth['ATT&CK']}")
    # If import_type is deaful None, then assign to default)

    # 1. get the specific typeql names for an object into a dictionary
    #logger.debug(f'through to decisions, attack is {attack_object}, sub technqiue {subtechnique}')
    #logger.debug(f'auth stix {auth["STIX21"]}, attack auth {auth["ATT&CK"]}')


    if auth['STIX21'] and not auth["ATT&CK"]:
        if stix_model.contains_data(sdo_type):
            # dispatch specific stix properties plus later on, generic sdo properties
            protocol = "stix21"
            obj_tql = copy.deepcopy(stix_model.get_data(sdo_type))
            is_list.extend(auth["is_lists"]["sdo"][tql_name])
        elif os_threat_model.contains_data(sdo_type):
            # dispatch specific stix properties plus later on, generic sdo properties
            protocol = "os-threat"
            obj_tql = copy.deepcopy(os_threat_model.get_data(sdo_type))
            is_list.extend(auth["is_lists"]["sdo"][tql_name])
            if tql_name == "sequence":
                tql_name = "-".join(step_type.split("_"))
        else:
            logger.error(f'obj_type type {sdo_type} not supported')
            return {}, "", {}, ""
    # - mitre attack_setting import
    elif auth['STIX21'] and auth["ATT&CK"]:
        if attack_object:
            logger.debug("I'm processing an attack decision")
            is_list.extend(auth["is_lists"]["sdo"]["attack"])
            protocol = "attack"
            attack_type = ''
            obj_tql = copy.deepcopy(attack_model.get_base("attack_base"))
            # Convert from stix-type to attack-tql-entity
            for model in attack_model.get_mapping("object_conversion"):
                logger.debug(f'chacking models, type is {model["type"]}')
                if model["type"] == sdo_type:
                    attack_type = model["typeql"]
                    logger.debug(f'attack type is {attack_type}')
                    if attack_type == "technique" and subtechnique:
                        attack_type = "sub-technique"
                    obj_tql.update(attack_model.get_data(attack_type))
                    is_list.extend(auth["is_lists"]["sdo"][attack_type])
                    logger.debug("updated")
                    break
            # Else log an error
            if not attack_type:
                logger.error(f'obj_type type {sdo_type} not in attack type conversion dict, type_to_tql_name')
                return {}, "", {}, ""
            else:
                tql_name = attack_type

        else:
            # its a Stix object, not an AT&CK one
            if stix_model.contains_data(sdo_type):
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                protocol = "stix21"
                obj_tql = copy.deepcopy(stix_model.get_data(sdo_type))
                is_list.extend(auth["is_lists"]["sdo"][tql_name])
            elif os_threat_model.contains_data(sdo_type):
                # dispatch specific stix properties plus later on, generic sdo properties
                protocol = "os-threat"
                obj_tql = copy.deepcopy(os_threat_model.get_data(sdo_type))
                is_list.extend(auth["is_lists"]["sdo"][tql_name])
                if tql_name == "sequence" and step_type != "sequence":
                    tql_name = "-".join(step_type.split("_"))
            else:
                logger.error(f'obj_type type {sdo_type} not in stix_models["dispatch_stix"] or dispatch mitre')
                return {}, "", {}, ""

    else:
        logger.error(f'import type {import_type} not supported')
        return {}, "", {}, ""

    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    logger.debug("about to update stuff")
    logger.debug(f'tql nme {tql_name}, sdo-type {sdo_type}')
    obj_tql.update(stix_model.get_base("base_sdo"))
    is_list.extend(auth["is_lists"]["sdo"]["sdo"])
    logger.debug("about to return from decisions")

    return obj_tql, tql_name, is_list, protocol


def sro_type_to_tql(sro_type: str,
                    sro_sub_type: str,
                    import_type:ImportType=default_import_type,
                    attack_object=False,
                    uses_relation=False,
                    is_procedure=False) -> [dict, str, list, str]:
    """ convert Stix object into a data model for processing

        Args:
            sro_type: the Stix2 type
            sro_sub_type: the relationship type
            import_type (): the type of import to use


        Returns:
            obj_tql : the dict of the tql properties
            tql_name : the typeql name of the object
            is_list: a list of all the porperties that are lists

    """
    # - list of property names that have values, and do not include False values
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    obj_tql = {}
    protocol = ""
    sro_tql_name = sro_type
    if sro_sub_type != "":
        sro_tql_name = sro_sub_type
    is_list = copy.deepcopy(auth["is_lists"]["sro"]["sro"])
    if sro_type == "sighting":
        is_list.extend(auth["is_lists"]["sro"]["sighting"])
    # If import_type is deaful None, then assign to default)
    if not import_type:
        import_type = default_import_type

    if auth['STIX21'] and not auth["ATT&CK"]:
        if stix_model.contains_data(sro_type):
            # dispatch specific stix properties plus later on, generic sdo properties
            protocol = "stix21"
            obj_tql = copy.deepcopy(stix_model.get_data(sro_type))
        elif auth["os-intel"] or auth["os-hunt"] and os_threat_model.contains_data(sro_type):
            # dispatch specific stix properties plus later on, generic sdo properties
            protocol = "os-threat"
            obj_tql = copy.deepcopy(os_threat_model.get_data(sro_type))
        else:
            logger.error(f'stixobj_type type {sro_type} not supported stix relation')
            return {}, "", []
    # - mitre attack_setting import
    elif auth['STIX21'] and auth["ATT&CK"]:
        if attack_object:
            is_list.extend(auth["is_lists"]["sro"]["attack"])
            protocol = "attack"
            attack_type = ''
            obj_tql = copy.deepcopy(attack_model.get_base("attack_base"))
            obj_tql.update(stix_model.get_data("relationship"))
            obj_tql.update({"x_mitre_platforms": "x-mitre-platforms"})
            # Convert from stix-type to attack-tql-entity
            for model in auth["reln"]["relations_sro_roles"]:
                if model["stix"] == sro_sub_type:
                    attack_type = model["typeql"]
                    #obj_tql.update(attack_models["data"][attack_type])
                    if uses_relation and is_procedure:
                        attack_type = "procedure"
                    break
            # Else log an error
            if not attack_type:
                logger.error(f'obj_type type {sro_type} not in attack type conversion dict, type_to_tql_name')
                return {}, "", []
            else:
                sro_tql_name = attack_type

        else:
            # its a Stix object, not an AT&CK one
            if stix_model.contains_data(sro_type):
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                protocol = "stix21"
                obj_tql = copy.deepcopy(stix_model.get_data(sro_type))
            elif os_threat_model.contains_data(sro_type) and auth["os-intel"] or auth["os-hunt"]:
                # dispatch specific stix properties plus later on, generic sdo properties
                protocol = "os-threat"
                obj_tql = copy.deepcopy(os_threat_model.get_data(sro_type))
            else:
                logger.error(f'obj_type type {sro_type} not in not any supported stix relation ')
                return {}, "", []

    else:
        logger.error(f'import type {import_type} not supported')
        return {}, "", []

    # - add on the generic sro properties
    obj_tql.update(stix_model.get_base("base_sro"))

    return obj_tql, sro_tql_name, is_list, protocol


def sco__type_to_tql(sco_type: str, import_type=default_import_type) -> [Dict[str, str], str, List[str], str]:
    """ convert Stix object into a data model for processing

        Args:
            sco_type (): the Stix2 sco type
            import_type (): the type of import to use

        Returns:
            obj_tql : a list of all properties
            obj_tql : the dict of the twl proeprties
            is_list: a list of all the porperties that are lists

    """
    # Based on import type setup observables
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    protocol = ""
    is_list = copy.deepcopy(auth["is_lists"]["sco"]["sco"])
    is_list.extend(auth["is_lists"]["sco"][sco_type])

    # - get the object-specific typeql names, sighting or relationship
    sco_tql_name = sco_type
    protocol = "stix21"
    obj_tql = copy.deepcopy(auth["objects"][sco_type])
    # - add on the generic sro properties
    obj_tql.update(stix_model.get_base("base_sco"))

    return obj_tql, sco_tql_name, is_list, protocol


def meta_type_to_tql(meta_type: str, import_type=default_import_type, attack_object=False) -> [Dict[str, str], str, List[str]]:
    """ convert Stix object into a data model for processing

        Args:
            meta_type (): the Stix2 meta type
            import_type (): the type of import to use

        Returns:
            obj_tql : a list of all properties
            obj_tql : the dict of the twl proeprties
            is_list: a list of all the porperties that are lists

    """
    # Based on import type setup observables
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    is_list = copy.deepcopy(auth["is_lists"]["sdo"]["sdo"])
    is_list.extend(auth["is_lists"]["meta"]["marking-definition"])
    meta_tql_name = meta_type
    obj_tql = copy.deepcopy(auth["objects"]["marking-definition"])
    # - add on the generic sro properties
    obj_tql.update(stix_model.get_base("base_sdo"))

    # - get the object-specific typeql names, sighting or relationship
    if attack_object:
        is_list.extend(auth["is_lists"]["sdo"]["attack"])
        obj_tql.update(attack_model.get_base("attack_base"))
        protocol = "attack"
        meta_tql_name = "attack-marking"
    else:
        protocol = "stix21"
        meta_tql_name = "statement-marking"

    return obj_tql, meta_tql_name, is_list, protocol


def get_source_from_id(stid: str, import_type: ImportType, protocol=""):
    """
        Get the source of the stix object
    Args:
        stid (): the stix-id of the object

    Returns:
        source: the source of the object
    """
    tmp_source = stid.split('--')[0]
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    source = ""
    if protocol != "":
        for model in auth["conv"]["sdo"]:
            if model["protocol"] == protocol and model["type"] == tmp_source:
                source = model["typeql"]
                if tmp_source == "sequence":
                    source = tmp_source
                return source
        for model in auth["conv"]["sro"]:
            if model["protocol"] == protocol and model["type"] == tmp_source:
                source = model["typeql"]
                if source == 'relationship' or source == "attack-relation":
                    source = 'stix-core-relationship'
                return source
        for model in auth["conv"]["sco"]:
            if model["protocol"] == protocol and model["type"] == tmp_source:
                source = model["typeql"]
                return source
        for model in auth["conv"]["meta"]:
            if model["protocol"] == protocol and model["type"] == tmp_source:
                source = model["typeql"]
                return source
    for model in auth["conv"]["sdo"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            if tmp_source == "sequence":
                source = tmp_source
            return source
    for model in auth["conv"]["sro"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            if source == 'relationship' or source == "attack-relation":
                source = 'stix-core-relationship'
            return source
    for model in auth["conv"]["sco"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            return source
    for model in auth["conv"]["meta"]:
        if model["type"] == tmp_source:
            source = model["typeql"]
            return source
    return source


def get_embedded_match(source_id: str, import_type: ImportType, i=0, protocol=""):
    """
        Assemble the typeql variable and match statement given the stix-id, and the increment
    Args:
        source_id (): stix-id to use
        i (): number of times this type of object has been used

    Returns:
        source_var, the typeql string of the variable
        match, the typeql match statement
    """
    source_type = get_source_from_id(source_id, import_type, protocol)
    source_var = '$' + source_type + str(i)
    if source_type == 'relationship' or source_type == "attack-relation":
        source_type = 'stix-core-relationship'
    match = f' {source_var} isa {source_type}, has stix-id "{source_id}";\n'
    return source_var, match


def get_full_object_match(source_id: str, import_type: ImportType, protocol: str):
    """
        Return a typeql match statement for this stix object
    Args:
        source_id (): the stix-id to look for

    Returns:
        source_var, the typeql string of the variable
        match, the typeql match statement
    """
    source_var, match = get_embedded_match(source_id, import_type, 0, protocol)
    match += source_var + ' has $properties;\n'
    # match += '$embedded (owner:' + source_var + ', pointed-to:$point ) isa embedded;\n'
    return source_var, match
