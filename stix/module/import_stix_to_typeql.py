import json
import types
import datetime
import re

from stix2 import *
from stix2.v21 import *
from stix2.utils import is_object, is_stix_type, get_type_from_id, is_sdo, is_sco, is_sro
from stix2.parsing import parse
from stix.module.definitions.stix21 import stix_models
from stix.module.definitions.attack import attack_models

from stix.module.import_stix_utilities import clean_props, get_embedded_match, split_on_activity_type, \
    add_property_to_typeql, add_relation_to_typeql, val_tql

import logging

logger = logging.getLogger(__name__)

default_import_type = {"STIX21": True, "CVE": False, "identity": False, "location": False, "rules": False,
                       "ATT&CK": False, "ATT&CK_Versions": ["12.0"],
                       "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"], "CACAO": False}


##############################################################
#  1.) Methods to Add 2_tql() Capability to all Stix Objects
############################################################

# ---------------------------------------------------
# 1.0) Helper method to direct the right typeql method to an incoming Stix object
# ---------------------------------------------------


def stix2_to_typeql(stix_object, import_type=None):
    """
    Initial function to convert Stix into typeql, it adds together the match and insert statements

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        typeql: a string of typeql to match and insert the object int typedb

    """
    match, insert, dep_obj = stix2_to_match_insert(stix_object, import_type)
    typeql = match + insert

    return typeql, dep_obj


def stix2_to_match_insert(stix_object, import_type=None):
    """
    Initial function to convert Stix into match/insert statments

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        match: a typeql match statement for this object
        insert: a typeql insert statement for this object

    """
    dep_match, dep_insert, indep_ql, core_ql, dep_obj = raw_stix2_to_typeql(stix_object, import_type)
    if dep_match == '':
        match = ''
    else:
        match = 'match ' + dep_match
    if indep_ql == '' and dep_insert == '':
        insert = ''
    else:
        insert = 'insert ' + indep_ql + dep_insert

    return match, insert, dep_obj


def raw_stix2_to_typeql(stix_object, import_type=None):
    """
    Initial function to convert Stix into typeql, it splits the incoming object into different
    channels based on its object type: sdo, sro, sco or meta

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    if import_type is None:
        import_type = ['STIX21']
    if is_sdo(stix_object):
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = sdo_to_typeql(stix_object, import_type)
    elif is_sro(stix_object):
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = sro_to_typeql(stix_object, import_type)
    elif is_sco(stix_object):
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = sco_to_typeql(stix_object, import_type)
    elif stix_object.type == 'marking-definition':
        dep_match, dep_insert, indep_ql, core_ql, dep_obj = marking_definition_to_typeql(stix_object, import_type)
    else:
        logger.error(f'object type not supported: {stix_object.type}, import type {import_type}')
        dep_match, dep_insert, indep_ql, core_ql = ''
        dep_list = []

    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# -------------------------------------------------------------
# 1.1) SDO Object Method to convert a Python object --> typeql string
#                 -   
# -------------------------------------------------------------
def sdo_to_data(sdo, import_type=['STIX21']):
    """ convert Stix object into a data model for processing

    Args:
        sdo (): the Stix2 SDO object
        import_type (): the type of import to use

    Returns:
        total_props, : a list of all properties
        obj_tql : the dict of the tql properties

    """
    # - list of property names that have values
    total_props = sdo._inner
    total_props = clean_props(total_props)
    # - work out the type of object
    obj_type = sdo.type
    # 1.B) get the specific typeql names for an object into a dictionary
    # - stix import
    stix21 = import_type.get("STIX21", False)
    attack = import_type.get('ATT&CK', False)

    if stix21 and not attack:
        if obj_type in stix_models["dispatch_stix"]:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = stix_models["dispatch_stix"][obj_type]
        else:
            logger.error(f'obj_type type {obj_type} not supported')
            return {}, ''
    # - mitre attack import
    elif stix21 and attack:
        if obj_type[0:6] == "x-mitre":
            if obj_type in attack_models["dispatch_attack"]:
                # dispatch specific mitre properties plus deneric mitre properties plus later on, generic sdo properties
                obj_tql = attack_models["dispatch_attack"][obj_type]
                obj_tql.update(attack_models["attack_base_typeql"])
            else:
                logger.error(f'obj_type type {obj_type} not in attack_models')
                return {}, ''

        elif 'x_mitre_version' in sdo:
            # Its an Attack object, but with a Stix type, process each type
            if obj_type == 'attack-pattern':
                # if a technique, then split into technique and subechnique and get mitre properties
                if sdo['x_mitre_is_subtechnique']:
                    obj_tql = attack_models["subtechnique_typeql"]
                    obj_tql.update(attack_models["attack_base_typeql"])
                elif not sdo['x_mitre_is_subtechnique']:
                    obj_tql = attack_models["technique_typeql"]
                    obj_tql.update(attack_models["attack_base_typeql"])
                else:
                    logger.error(f'obj_type type {obj_type} not a technique or subtechnique')
                    return {}, ''
            elif obj_type == 'campaign':
                # the object is a campaign, get mitre properties
                obj_tql = attack_models["campaign_typeql"][obj_type]
                obj_tql.update(attack_models["attack_base_typeql"])
            elif obj_type == 'course-of-action':
                # the object is a mitigation, get mitre properties
                obj_tql = attack_models["mitigation_typeql"][obj_type]
                obj_tql.update(attack_models["attack_base_typeql"])
            elif obj_type == 'intrusion-set':
                # the object is a group, get mitre properties
                obj_tql = attack_models["group_typeql"][obj_type]
                obj_tql.update(attack_models["attack_base_typeql"])
            elif obj_type == 'malware':
                # the object is a software-malware, get mitre properties
                obj_tql = attack_models["software_malware_typeql"][obj_type]
                obj_tql.update(attack_models["attack_base_typeql"])
            elif obj_type == 'tool':
                # the object is a software-tool, get mitre properties
                obj_tql = attack_models["software_tool_typeql"][obj_type]
                obj_tql.update(attack_models["attack_base_typeql"])
            else:
                logger.error(f'obj_type type {obj_type} has a mitre field, but is not a mitre object')
                return {}, ''

        else:
            # its a Stix object, not an AT&CK one
            if obj_type in stix_models["dispatch_stix"]:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = stix_models["dispatch_stix"][obj_type]
                obj_tql2 = stix_models["dispatch_stix"][obj_type]
                obj_tql.update(obj_tql2)
            else:
                logger.error(f'obj_type type {obj_type} not in stix_models["dispatch_stix"] or dispatch mitre')
                return {}, ''

    else:
        logger.error(f'import type {import_type} not supported')
        return {}, ''

    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    obj_tql.update(stix_models["sdo_typeql_dict"])

    return total_props, obj_tql


def sdo_to_typeql(sdo, import_type='STIX21'):
    """
    Initial function to convert Stix2 SDO object into typeql

    Args:
        sdo (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    # 1.A) get configuration parameters
    # - variable for use in typeql statements
    sdo_var = '$' + sdo.type
    dep_list = []
    # 1.B) get the data model
    total_props, obj_tql = sdo_to_data(sdo, import_type)
    if obj_tql == '':
        return '', '', '', '', {}
    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 2.) setup the typeql statement for the sdo entity
    indep_ql = sdo_var + ' isa ' + sdo.type
    core_ql = sdo_var + ' isa ' + sdo.type + ', has stix-id $stix-id;\n$stix-id ' + val_tql(sdo.id) + ';\n'
    indep_ql_props = dep_match = dep_insert = ''

    # 3.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        indep_ql2, indep_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sdo, prop_var_list)
        # then add them all together
        indep_ql += indep_ql2
        indep_ql_props += indep_ql_props2
        # add a terminator on the end of the query statement
    indep_ql += ";\n" + indep_ql_props + "\n\n"

    # 4.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel, sdo, sdo_var, prop_var_list, j)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    dep_obj = {"id": sdo.id, "dep_list": dep_list, "type": sdo.type}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# -------------------------------------------------------
# 1.2) SRO Object Method to convert a Python object --> typeql string
#                 -   
# -----------------------------------------------------
def sro_to_data(sro, import_type='STIX21'):
    """ convert Stix object into a data model for processing

        Args:
            sro (): the Stix2 sco object
            import_type (): the type of import to use

        Returns:
            total_props, : a list of all properties
            obj_tql : the dict of the twl proeprties

    """
    # - list of property names that have values, and do not include False values
    total_props = sro._inner
    total_props = clean_props(total_props)

    # - work out the type of object
    obj_type = sro.type
    stix21 = import_type.get("STIX21", False)
    attack = import_type.get('ATT&CK', False)

    if stix21 and not attack:
        if obj_type in stix_models["dispatch_stix"]:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = stix_models["dispatch_stix"][obj_type]
        else:
            logger.error(f'obj_type type {obj_type} not supported stix relation')
            return {}, ''
    # - mitre attack import
    elif stix21 and attack:
        if sro['relationship_type'] == 'uses' and sro['target_ref'][0:13] == 'attack-pattern':
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = stix_models["dispatch_stix"][obj_type]
            obj_tql.update(attack_models["attack_base_typeql"])
        elif obj_type in stix_models["dispatch_stix"]:
            # dispatch specific stix properties plus later on, generic sdo properties
            obj_tql = stix_models["dispatch_stix"][obj_type]
        else:
            logger.error(f'obj_type type {obj_type} not supported stix relation')
            return {}, ''

    # - add on the generic sro properties
    obj_tql.update(stix_models["sro_base_typeql_dict"])

    return total_props, obj_tql


def sro_to_typeql(sro, import_type='STIX21'):
    """
    Initial function to convert Stix2 SRO object into typeql

    Args:
        sro (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sro_var = '$' + sro.type
    dep_list = []
    # - work out the type of object
    obj_type = sro.type
    total_props, obj_tql = sro_to_data(sro, import_type)
    if obj_tql == '':
        return '', '', '', '', {}
    # initialise the typeql insert statement
    dep_match = dep_insert = indep_ql = core_ql = dep_insert_props = ''

    # 2.) setup the match statements first, depending on whether the object is a sighting or a relationship
    # A. If it is a Relationship then find the source and target roles for the relation, and match them in
    if obj_type == 'relationship':
        source_id = sro.source_ref
        dep_list.append(source_id)
        source_var, source_match = get_embedded_match(source_id)
        target_id = sro.target_ref
        dep_list.append(target_id)
        target_var, target_match = get_embedded_match(target_id)
        dep_match += source_match + target_match
        # 3.)  then setup the typeql statement to insert the specific sro relation, from the dict, with the matches
        for record in stix_models["stix_rel_roles"]:
            if record['stix'] == sro["relationship_type"]:
                dep_insert += '\n' + sro_var
                dep_insert += ' (' + record['source'] + ':' + source_var
                dep_insert += ', ' + record['target'] + ':' + target_var + ')'
                dep_insert += ' isa ' + record['typeql']
                core_ql = sro_var + ' isa ' + record['typeql']
                core_ql += ', has stix-id $stix-id;\n$stix-id ' + val_tql(sro.id) + ';\n'
                break
                # B. If it is a Sighting then match the object to the sighting
    elif obj_type == 'sighting':
        sighting_of_id = sro.sighting_of_ref
        dep_list.append(sighting_of_id)
        sighting_of_var, sighting_of_match = get_embedded_match(sighting_of_id)
        dep_match += ' \n' + sighting_of_match
        dep_insert += '\n' + sro_var + ' (sighting-of:' + sighting_of_var
        # if there is observed data list, then add it to the match statement
        observed_data_list = sro.get("observed_data_refs")
        if (observed_data_list != None) and (len(observed_data_list) > 0):
            for i, observed_data_id in enumerate(observed_data_list):
                dep_list.append(observed_data_id)
                observed_data_var, observed_data_match = get_embedded_match(observed_data_id, i)
                dep_match += observed_data_match
                dep_insert += ', observed:' + observed_data_var
        # if there is a list of who and where the sighting's occured, then match it in
        where_sighted_list = sro.get("where_sighted_refs")
        if (where_sighted_list != None) and (len(where_sighted_list) > 0):
            for where_sighted_id in where_sighted_list:
                dep_list.append(where_sighted_id)
                where_sighted_var, where_sighted_match = get_embedded_match(where_sighted_id)
                dep_match += where_sighted_match
                dep_insert += ', where-sighted:' + where_sighted_var

        # then finalise the typeql statement for the sro sighting
        dep_insert += ') isa sighting'
        core_ql = sro_var + ' ($role:$any) isa sighting'
        core_ql += ', has stix-id $stix-id;\n$stix-id ' + val_tql(sro.id) + ';\n'
    else:
        logger.error(f'relationship type {obj_type} not supported')
        return ''

    # 4.) next, split total properties into actual properties and nested structures (Relations)
    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 5.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        dep_insert2, dep_insert_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sro, prop_var_list)
        # then add them all together
        dep_insert += dep_insert2
        dep_insert_props += dep_insert_props2
        # add a terminator on the end of the query statement
    dep_insert += ";\n" + dep_insert_props + "\n\n"

    # 6.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel, sro, sro_var, prop_var_list, j)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    dep_obj = {"id": sro.id, "dep_list": dep_list, "type": "relation"}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# ---------------------------------------------------
# 1.3) SCO Object Method to convert a Python object --> typeql string
#                 -
# --------------------------------------------------
def sco_to_data(sco, import_type='STIX21'):
    """ convert Stix object into a data model for processing

        Args:
            sco (): the Stix2 sco object
            import_type (): the type of import to use

        Returns:
            total_props, : a list of all properties
            obj_tql : the dict of the twl proeprties

    """
    # - list of property names that have values
    total_props = sco._inner
    total_props = clean_props(total_props)
    # print(properties)
    # - work out the type of object
    obj_type = sco.type
    # - get the object-specific typeql names, sighting or relationship
    obj_tql = stix_models["dispatch_stix"][obj_type]
    # - add on the generic sro properties
    obj_tql.update(stix_models["sco_base_typeql_dict"])

    return total_props, obj_tql


def sco_to_typeql(sco, import_type='STIX21'):
    """
    Initial function to convert Stix2 SCO object into typeql

    Args:
        sco (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sco_var = '$' + sco.type
    dep_list = []
    # initialise the typeql insert statement
    dep_match = dep_insert = indep_ql = core_ql = dep_insert_props = ''

    # 1.C) Split them into properties and relations
    total_props, obj_tql = sco_to_data(sco, import_type)
    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 2.) setup the typeql statement for the sco entity
    dep_insert = sco_var + ' isa ' + sco.type
    core_ql = sco_var + ' isa ' + sco.type + ', has stix-id $stix-id;\n$stix-id ' + val_tql(sco.id) + ';\n'

    # 3.) add each of the properties and values of the properties to the typeql statement
    # 5.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        dep_insert2, dep_insert_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sco, prop_var_list)
        # then add them all together
        dep_insert += dep_insert2
        dep_insert_props += dep_insert_props2
        # add a terminator on the end of the insert statement
    dep_insert += ";\n" + dep_insert_props + "\n\n"

    # 6.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        dep_match2, dep_insert2, dep_list2 = add_relation_to_typeql(rel, sco, sco_var, prop_var_list, j)
        # then add it back together
        dep_match = dep_match + dep_match2
        dep_insert = dep_insert + dep_insert2
        dep_list = dep_list + dep_list2

    dep_obj = {"id": sco.id, "dep_list": dep_list, "type": sco.type}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj


# ---------------------------------------------------
# 1.4) Meta Object Method to convert a Python object --> typeql string
#                 -  marking definitions, statement, colour and Mitre copyright
# --------------------------------------------------


def marking_definition_to_typeql(stix_object, import_type="STIX21"):
    """
    Initial function to convert Stix2 marking object into typeql

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        dep_match: a typeql match statement that depends on other objects
        dep_insert: a typeql insert statement that depends on other objects
        indep_ql: a typeql insert statement with no extenral dependencies
        core_ql: a typeql insert statement that describes the object head, so the independent and dependent parts can be injected seaparately

    """
    dep_list = []
    dep_match = dep_insert = indep_ql = core_ql = ''
    # if the marking is a colour, match it in, else it is a statement type
    if stix_object.definition_type == "statement":
        indep_ql = '\n $marking isa statement-marking'
        indep_ql += ',\n has statement ' + val_tql(stix_object.definition.statement)
        indep_ql += ',\n has stix-type "marking-definition"'
        indep_ql += ',\n has stix-id ' + val_tql(stix_object.id)
        indep_ql += ',\n has created ' + val_tql(stix_object.created)
        indep_ql += ',\n has spec-version ' + val_tql(stix_object.spec_version)
        indep_ql += ';\n'
        core_ql = '$marking isa statement-marking'
        core_ql += ', has stix-id $stix-id;\n$stix-id ' + val_tql(stix_object.id)
        core_ql += ';'

    dep_obj = {"id": stix_object.id, "dep_list": dep_list, "type": "marking"}
    return dep_match, dep_insert, indep_ql, core_ql, dep_obj
