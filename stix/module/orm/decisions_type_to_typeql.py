from stix.module.definitions.stix21 import stix_models
from stix.module.definitions.attack import attack_models
from stix.module.definitions.os_threat import os_threat_models
from stix.module.authorise import authorised_mappings

import logging

logger = logging.getLogger(__name__)


default_import_type = {
    'STIX21': True,
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


def sdo_type_to_tql(sdo_type, import_type=None, attack_object=False, subtechnique=False):
    """ convert Stix object into a data model for processing

    Args:
        sdo_type (): the Stix2 SDO type
        import_type (): the type of import to use

    Returns:
        obj_tql : the dict of the tql properties
        tql_name : the typeql name of the object

    """
    auth = authorised_mappings(import_type)
    obj_tql = {}
    tql_name = sdo_type
    # If import_type is deaful None, then assign to default)
    if not import_type:
        import_type = default_import_type

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
            return "", ""
    # - mitre attack_setting import
    elif auth['STIX21'] and auth["ATT&CK"]:
        if attack_object:
            attack_type = ''
            obj_tql = attack_models["base"][sdo_type]
            # Convert from stix-type to attack-tql-entity
            for model in attack_models["mappings"]["object_conversion"]:
                if model["type"] == sdo_type:
                    attack_type = model["typeql"]
                    if attack_type == "technique":
                        if subtechnique:
                            attack_type = "sub-technique"
                    obj_tql.update(attack_models["data"][attack_type])
                    break
            # Else log an error
            if not attack_type:
                logger.error(f'obj_type type {sdo_type} not in attack type conversion dict, type_to_tql_name')
                return "", ""
            else:
                tql_name = attack_type

        else:
            # its a Stix object, not an AT&CK one
            if sdo_type in stix_models:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = stix_models[sdo_type]
            elif sdo_type in os_threat_models:
                # dispatch specific stix properties plus later on, generic sdo properties
                obj_tql = os_threat_models[sdo_type]
            else:
                logger.error(f'obj_type type {sdo_type} not in stix_models["dispatch_stix"] or dispatch mitre')
                return "", ""

    else:
        logger.error(f'import type {import_type} not supported')
        return "", ""

    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    obj_tql.update(stix_models["base"]["base_sdo"])

    return obj_tql, tql_name


def sro_type_to_tql(sro_type, import_type=None, attack_object=False, uses_relation=False, is_procedure=False):
    """ convert Stix object into a data model for processing

        Args:
            sro_type: the Stix2 type
            import_type (): the type of import to use

        Returns:
            obj_tql : the dict of the tql properties
            tql_name : the typeql name of the object

    """
    # - list of property names that have values, and do not include False values
    auth = authorised_mappings(import_type)
    obj_tql = {}
    sro_tql_name = sro_type
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
            return "", ""
    # - mitre attack_setting import
    elif auth['STIX21'] and auth["ATT&CK"]:
        if attack_object:
            attack_type = ''
            obj_tql = attack_models["base"]["attack_base"]
            # Convert from stix-type to attack-tql-entity
            for model in attack_models["mappings"]["type_to_tql_name"]:
                if model["type"] == sro_type:
                    attack_type = model["typeql"]
                    obj_tql.update(attack_models["data"][attack_type])
                    if uses_relation and is_procedure:
                        attack_type = "procedure"
                    break
            # Else log an error
            if not attack_type:
                logger.error(f'obj_type type {sro_type} not in attack type conversion dict, type_to_tql_name')
                return "", ""
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
                return "", ""

    else:
        logger.error(f'import type {import_type} not supported')
        return "", ""

    # - add on the generic sro properties
    obj_tql.update(stix_models["base"]["base_sro"])

    return obj_tql, sro_tql_name


def sco__type_to_tql(sco_type, import_type=None):
    """ convert Stix object into a data model for processing

        Args:
            sco (): the Stix2 sco object
            import_type (): the type of import to use

        Returns:
            : a list of all properties
            obj_tql : the dict of the twl proeprties

    """
    # If import_type is deaful None, then assign to default)
    if not import_type:
        import_type = default_import_type
    # - get the object-specific typeql names, sighting or relationship
    sco_tql_name = sco_type
    obj_tql = stix_models["data"][sco_type]
    # - add on the generic sro properties
    obj_tql.update(stix_models["base"]["base_sco"])

    return obj_tql, sco_tql_name