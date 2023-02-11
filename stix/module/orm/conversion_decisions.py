from stix.module.definitions.stix21 import stix_models
from stix.module.definitions.attack import attack_models
from stix.module.definitions.os_threat import os_threat_models
from stix.module.authorise import authorised_mappings, default_import_type

import logging

logger = logging.getLogger(__name__)


def sdo_type_to_tql(sdo_type, import_type=default_import_type,
                    attack_object=False, subtechnique=False) -> [dict, str, dict]:
    """ convert Stix object into a data model for processing

    Args:
        sdo_type (): the Stix2 SDO type
        import_type (): the type of import to use

    Returns:
        obj_tql : the dict of the tql properties
        tql_name : the typeql name of the object
        is_list: a list of all the porperties that are lists

    """
    auth = authorised_mappings(import_type)
    obj_tql = {}
    is_list =[]
    tql_name = sdo_type
    print("in sdo decisions")
    print(f'obj tql {obj_tql}')
    print(f"variables, stix {auth['STIX21']}, attack is {auth['ATT&CK']}")
    # If import_type is deaful None, then assign to default)

    # 1. get the specific typeql names for an object into a dictionary
    #print(f'through to decisions, attack is {attack_object}, sub technqiue {subtechnique}')
    #print(f'auth stix {auth["STIX21"]}, attack auth {auth["ATT&CK"]}')

    if auth['STIX21'] and not auth["ATT&CK"]:
        if sdo_type in stix_models["data"]:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = stix_models["data"][sdo_type]
        elif auth["case"] or auth["feed"] and sdo_type in os_threat_models:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = os_threat_models["data"][sdo_type]
        else:
            logger.error(f'obj_type type {sdo_type} not supported')
            return {}, "", []
    # - mitre attack_setting import
    elif auth['STIX21'] and auth["ATT&CK"]:
        if attack_object:
            print("I'm processing an attack decision")
            is_list.extend(auth["is_lists"]["sdo"]["attack"])
            attack_type = ''
            obj_tql = attack_models["base"]["attack_base"]
            # Convert from stix-type to attack-tql-entity
            for model in attack_models["mappings"]["object_conversion"]:
                print(f'chacking models, type is {model["type"]}')
                if model["type"] == sdo_type:
                    attack_type = model["typeql"]
                    print(f'attack tye is {attack_type}')
                    if attack_type == "technique" and subtechnique:
                        attack_type = "subtechnique"
                    obj_tql.update(attack_models["data"][attack_type])
                    print("updated")
                    break
            # Else log an error
            if not attack_type:
                logger.error(f'obj_type type {sdo_type} not in attack type conversion dict, type_to_tql_name')
                return {}, "", []
            else:
                tql_name = attack_type

        else:
            # its a Stix object, not an AT&CK one
            if sdo_type in stix_models["data"]:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = stix_models["data"][sdo_type]
            elif sdo_type in os_threat_models["data"]:
                # dispatch specific stix properties plus later on, generic sdo properties
                obj_tql = os_threat_models["data"][sdo_type]
            else:
                logger.error(f'obj_type type {sdo_type} not in stix_models["dispatch_stix"] or dispatch mitre')
                return {}, "", []

    else:
        logger.error(f'import type {import_type} not supported')
        return {}, "", []

    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    print("about to update stuff")
    print(f'tql nme {tql_name}, sdo-type {sdo_type}')
    obj_tql.update(stix_models["base"]["base_sdo"])
    is_list.extend(auth["is_lists"]["sdo"][tql_name])
    is_list.extend(auth["is_lists"]["sdo"]["sdo"])
    print("about to return from deci9sions")

    return obj_tql, tql_name, is_list


def sro_type_to_tql(sro_type, sro_sub_type,import_type=default_import_type,
                    attack_object=False, uses_relation=False, is_procedure=False) -> [dict, str, list]:
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
    auth = authorised_mappings(import_type)
    obj_tql = {}
    sro_tql_name = sro_type
    if sro_sub_type != "":
        sro_tql_name = sro_sub_type
    is_list = auth["is_lists"]["sro"]["sro"]
    if sro_type == "sighting":
        is_list.extend(auth["is_lists"]["sro"]["sighting"])
    # If import_type is deaful None, then assign to default)
    if not import_type:
        import_type = default_import_type

    if auth['STIX21'] and not auth["ATT&CK"]:
        if sro_type in stix_models["data"]:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = stix_models["data"][sro_type]
        elif auth["os-intel"] or auth["os-hunt"] and sro_type in os_threat_models["data"]:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = os_threat_models["data"][sro_type]
        else:
            logger.error(f'obj_type type {sro_type} not supported stix relation')
            return {}, "", []
    # - mitre attack_setting import
    elif auth['STIX21'] and auth["ATT&CK"]:
        if attack_object:
            is_list.extend(auth["is_lists"]["sro"]["attack"])
            attack_type = ''
            obj_tql = attack_models["base"]["attack_base"]
            # Convert from stix-type to attack-tql-entity
            for model in attack_models["mappings"]["object_conversion"]:
                if model["type"] == sro_type:
                    attack_type = model["typeql"]
                    obj_tql.update(attack_models["data"][attack_type])
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
            if sro_type in stix_models["data"]:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = stix_models["data"][sro_type]
            elif sro_type in os_threat_models["data"] and auth["os-intel"] or auth["os-hunt"]:
                # dispatch specific stix properties plus later on, generic sdo properties
                obj_tql = os_threat_models["data"][sro_type]
            else:
                logger.error(f'obj_type type {sro_type} not in not any supported stix relation ')
                return {}, "", []

    else:
        logger.error(f'import type {import_type} not supported')
        return {}, "", []

    # - add on the generic sro properties
    obj_tql.update(stix_models["base"]["base_sro"])

    return obj_tql, sro_tql_name, is_list


def sco__type_to_tql(sco_type, import_type=default_import_type) -> [dict, str, list]:
    """ convert Stix object into a data model for processing

        Args:
            sco (): the Stix2 sco object
            import_type (): the type of import to use

        Returns:
            obj_tql : a list of all properties
            obj_tql : the dict of the twl proeprties
            is_list: a list of all the porperties that are lists

    """
    # Based on import type setup observables
    auth = authorised_mappings(import_type)
    is_list = auth["is_lists"]["sco"]["sco"]
    is_list.extend(auth["is_lists"]["sco"][sco_type])

    # - get the object-specific typeql names, sighting or relationship
    sco_tql_name = sco_type
    obj_tql = stix_models["data"][sco_type]
    # - add on the generic sro properties
    obj_tql.update(stix_models["base"]["base_sco"])

    return obj_tql, sco_tql_name, is_list
