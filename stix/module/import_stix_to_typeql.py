import json
import types
import datetime

from stix2 import *
from stix2.v21 import *
from stix2.utils import is_object, is_stix_type, get_type_from_id, is_sdo, is_sco, is_sro
from stix2.parsing import parse
from stix.module.definitions.stix21 import stix_models

from stix.module.import_stix_utilities import clean_props,get_embedded_match,split_on_activity_type,add_property_to_typeql,add_relation_to_typeql, val_tql

import logging
logger = logging.getLogger(__name__)
##############################################################
#  1.) Methods to Add 2_tql() Capability to all Stix Objects
############################################################

#---------------------------------------------------
# 1.0) Helper method to direct the right typeql method to an incoming Stix object
#---------------------------------------------------


def stix2_to_typeql(stix_object, import_type='STIX21'):
    """
    Initial function to convert Stix into typeql, it adds together the match and insert statements

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        typeql: a string of typeql to match and insert concepts in typedb

    """
    match, insert = raw_stix2_to_typeql(stix_object, import_type)
    typeql = match + insert
        
    return typeql


def raw_stix2_to_typeql(stix_object, import_type='STIX21'):
    """
    Initial function to convert Stix into typeql, it splits the incoming object into different
    channels based on its object type: sdo, sro, sco or meta

    Args:
        stix_object (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        match: a typeql match statement
        insert: a typeql insert statement

    """
    if is_sdo(stix_object):
        match, insert = sdo_to_typeql(stix_object, import_type)
    elif is_sro(stix_object):
        match, insert = sro_to_typeql(stix_object, import_type)
    elif is_sco(stix_object):
        match, insert = sco_to_typeql(stix_object, import_type)
    elif stix_object.type == 'marking-definition':
        match, insert = marking_definition_to_typeql(stix_object, import_type)
    else:
        logger.error(f'object type not supported: {stix_object.type}, import type {import_type}')
        match, insert = ''
        
    return match, insert


#-------------------------------------------------------------
# 1.1) SDO Object Method to convert a Python object --> typeql string
#                 -   
#-------------------------------------------------------------
def sdo_to_typeql(sdo, import_type='STIX21'):
    """
    Initial function to convert Stix2 SDO object into typeql

    Args:
        sdo (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        match: a typeql match statement
        insert: a typeql insert statement

    """
    # 1.A) get configuration parameters
    # - variable for use in typeql statements
    sdo_var = '$' + sdo.type
    # - list of property names that have values
    total_props = sdo._inner
    total_props = clean_props(total_props)
    # - work out the type of object
    obj_type = sdo.type
    # 1.B) get the specific typeql names for an object into a dictionary
    # - stix import
    if import_type == 'STIX21':
        if obj_type in stix_models["dispatch_stix"]:
            obj_tql = stix_models["dispatch_stix"][obj_type]
        else:
            logger.error(f'obj_type type {obj_type} not supported')
            return ''
    # - mitre attack import
    elif import_type == 'ATT&CK':
        if obj_type[0:6] == "x-mitre":
            if obj_type in dispatch_attack:
                # dispatch specific mitre properties plus generic sdo properties
                obj_tql = dispatch_attack[obj_type]
            else:
                logger.error(f'obj_type type {obj_type} not in dispatch mitre')
                return ''
        else:
            if obj_type in stix_models["dispatch_stix"]:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = stix_models["dispatch_stix"][obj_type]
                obj_tql2 = dispatch_attack[obj_type]
                obj_tql.update(obj_tql2)
            else:
                logger.error(f'obj_type type {obj_type} not in stix_models["dispatch_stix"] or dispatch mitre')
                return ''              
        
    else:
        logger.error(f'import type {import_type} not supported')
        return ''	
    
    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    obj_tql.update(stix_models["sdo_typeql_dict"])
    properties, relations = split_on_activity_type(total_props, obj_tql)   
    
    # 2.) setup the typeql statement for the sdo entity
    type_ql = 'insert ' + sdo_var + ' isa ' + sdo.type 
    type_ql_props = match = insert = '' 
    
    # 3.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        type_ql2, type_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sdo, prop_var_list)
        # then add them all together
        type_ql += type_ql2
        type_ql_props += type_ql_props2        
    # add a terminator on the end of the query statement
    type_ql += ";\n" +  type_ql_props + "\n\n"
    
    # 4.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        match2, insert2 = add_relation_to_typeql(rel, sdo, sdo_var, prop_var_list, j)
        # then add it back together    
        match = match + match2
        insert = insert + insert2            
                         
    if match != '':
        match = 'match \n' + match + '\n'
    insert =   type_ql + insert
    return match, insert


#-------------------------------------------------------
# 1.2) SRO Object Method to convert a Python object --> typeql string
#                 -   
#-----------------------------------------------------


def sro_to_typeql(sro, import_type='STIX21'):
    """
    Initial function to convert Stix2 SRO object into typeql

    Args:
        sro (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        match: a typeql match statement
        insert: a typeql insert statement

    """
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sro_var = '$' + sro.type
    # - list of property names that have values, and do not include False values
    total_props = sro._inner
    total_props = clean_props(total_props)
    
    # - work out the type of object
    obj_type = sro.type
    # - get the object-specific typeql names, sighting or relationship
    obj_tql = stix_models["dispatch_stix"][obj_type]
    # - add on the generic sro properties
    obj_tql.update(stix_models["sro_base_typeql_dict"])
    #initialise the typeql insert statement
    type_ql = 'insert '    
    
    # 2.) setup the match statements first, depending on whether the object is a sighting or a relationship
    # A. If it is a Relationship then find the source and target roles for the relation, and match them in
    type_ql_sro_match = 'match \n'     
    if obj_type == 'relationship':
        source_id = sro.source_ref
        source_var, source_match = get_embedded_match(source_id)
        target_id = sro.target_ref 
        target_var, target_match = get_embedded_match(target_id)
        type_ql_sro_match += source_match + target_match
        # 3.)  then setup the typeql statement to insert the specific sro relation, from the dict, with the matches
        for record in stix_models["stix_rel_roles"]:
            if record['stix'] == sro["relationship_type"]:
                type_ql +=  '\n' + sro_var 
                type_ql += ' (' + record['source'] + ':' + source_var 
                type_ql += ', ' + record['target'] + ':' + target_var + ')'
                type_ql += ' isa ' + record['typeql'] 
                break              
    # B. If it is a Sighting then match the object to the sighting
    elif obj_type == 'sighting':
        sighting_of_id = sro.sighting_of_ref  
        sighting_of_var, sighting_of_match = get_embedded_match(sighting_of_id)
        type_ql_sro_match += ' \n' + sighting_of_match
        type_ql +=  '\n' + sro_var + ' (sighting-of:' + sighting_of_var 
        # if there is observed data list, then add it to the match statement
        observed_data_list = sro.get("observed_data_refs")
        if (observed_data_list != None) and (len(observed_data_list) > 0):
            for i, observed_data_id in enumerate(observed_data_list):
                observed_data_var, observed_data_match = get_embedded_match(observed_data_id,i)
                type_ql_sro_match += observed_data_match
                type_ql += ', observed:' + observed_data_var
        # if there is a list of who and where the sighting's occured, then match it in
        where_sighted_list = sro.get("where_sighted_refs")
        if (where_sighted_list != None) and (len(where_sighted_list) > 0):
            for where_sighted_id in where_sighted_list:
                where_sighted_var, where_sighted_match = get_embedded_match(where_sighted_id)
                type_ql_sro_match += where_sighted_match
                type_ql += ', where-sighted:' + where_sighted_var
        
        # then finalise the typeql statement for the sro sighting
        type_ql += ') isa sighting'
    else:
      logger.error(f'relationship type {obj_type} not supported')
      return ''
    
    # 4.) next, split total properties into actual properties and nested structures (Relations)
    properties, relations = split_on_activity_type(total_props, obj_tql) 
    match = type_ql_props = insert = ''
    
    # 5.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        type_ql2, type_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sro, prop_var_list)
        # then add them all together
        type_ql += type_ql2
        type_ql_props += type_ql_props2        
    # add a terminator on the end of the query statement
    type_ql += ";\n" +  type_ql_props + "\n\n"
    
    # 6.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):        
        # split off for relation processing
        match2, insert2 = add_relation_to_typeql(rel, sro, sro_var, prop_var_list, j)
        # then add it back together    
        match = match + match2
        insert = insert + insert2   
            
    match = type_ql_sro_match + match
    insert = type_ql + insert
    return match, insert


# ---------------------------------------------------
# 1.3) SCO Object Method to convert a Python object --> typeql string
#                 -
# --------------------------------------------------
def sco_to_typeql(sco, import_type='STIX21'):
    """
    Initial function to convert Stix2 SCO object into typeql

    Args:
        sco (): valid Stix2 object
        import_type (): string, either Stix2 or ATT&CK

    Returns:
        match: a typeql match statement
        insert: a typeql insert statement

    """
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sco_var = '$' + sco.type
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
    # initialise the typeql insert statement
    type_ql = 'insert '

    # 1.C) Split them into properties and relations
    properties, relations = split_on_activity_type(total_props, obj_tql)

    # 2.) setup the typeql statement for the sco entity
    type_ql = 'insert \n' + sco_var + ' isa ' + sco.type
    type_ql_props = match = insert = ''

    # 3.) add each of the properties and values of the properties to the typeql statement

    # 4.) next, split total properties into actual properties and nested structures (Relations)
    properties, relations = split_on_activity_type(total_props, obj_tql)
    type_ql_props = insert = ''
    match = ''

    # 5.) add each of the properties and values of the properties to the typeql statement
    prop_var_list = []
    for prop in properties:
        # split off for properties processing
        type_ql2, type_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, sco, prop_var_list)
        # then add them all together
        type_ql += type_ql2
        type_ql_props += type_ql_props2
        # add a terminator on the end of the insert statement
    type_ql += ";\n" + type_ql_props + "\n\n"

    # 6.) add each of the relations to the match and insert statements
    for j, rel in enumerate(relations):
        # split off for relation processing
        match2, insert2 = add_relation_to_typeql(rel, sco, sco_var, prop_var_list, j)
        # then add it back together
        match = match + match2
        insert = insert + insert2

    if match != '':
        match = 'match \n' + match + '\n'
    insert = type_ql + insert
    return match, insert


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
        match: a typeql match statement
        type_ql: a typeql insert statement

    """
    # if the marking is a colour, match it in, else it is a statement type
    if stix_object.definition_type == "statement":
        type_ql = '\n insert $marking isa statement-marking'
        type_ql += ',\n has statement ' + val_tql(stix_object.definition.statement)
        type_ql += ',\n has stix-type "marking-definition"'
        type_ql += ',\n has stix-id ' + val_tql(stix_object.id)
        type_ql += ',\n has created ' + val_tql(stix_object.created)
        type_ql += ',\n has spec-version ' + val_tql(stix_object.spec_version)
        type_ql += ';\n'
    elif stix_object.definition_type == "tlp":
        type_ql = ''

    match = ''
    return match, type_ql