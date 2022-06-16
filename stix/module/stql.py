import json
#import os
import types
import datetime
from loguru import logger
from stix2 import *
from stix2.v21 import *
from stix2.utils import is_object, is_stix_type, get_type_from_id, is_sdo, is_sco, is_sro
from stix2.parsing import parse
from stix.module.definitions.stix21 import stix_models

##############################################################
#  1.) Methods to Add 2_tql() Capability to all Stix Objects
############################################################

#---------------------------------------------------
# 1.0) Helper method to direct the right typeql method to an incoming Stix object
#---------------------------------------------------
def stix2_to_typeql(stix_object, import_type='Stix21'):
    match, insert = raw_stix2_to_typeql(stix_object, import_type)
    typeql = match + insert
        
    return typeql

def raw_stix2_to_typeql(stix_object, import_type='Stix21'):
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
def sdo_to_typeql(sdo, import_type='stix21'):
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
    if import_type == 'Stix21':
        if obj_type in dispatch_stix:
            obj_tql = dispatch_stix[obj_type]
        else:
            logger.error(f'obj_type type {obj_type} not supported')
            return ''
    # - mitre attack import
    elif import_type == 'mitre':
        if obj_type[0:6] == "x-mitre":
            if obj_type in dispatch_mitre:
                # dispatch specific mitre properties plus generic sdo properties
                obj_tql = dispatch_mitre[obj_type]
            else:
                logger.error(f'obj_type type {obj_type} not in dispatch mitre')
                return ''
        else:
            if obj_type in dispatch_stix:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = dispatch_stix[obj_type]
                obj_tql2 = dispatch_mitre[obj_type]
                obj_tql.update(obj_tql2)
            else:
                logger.error(f'obj_type type {obj_type} not in dispatch_stix or dispatch mitre')
                return ''              
        
    else:
        logger.error(f'import type {import_type} not supported')
        return ''	
    
    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    obj_tql.update(stix_models['sdo_typeql_dict'])
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


def sro_to_typeql(sro, import_type='stix21'):
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sro_var = '$' + sro.type
    # - list of property names that have values, and do not include False values
    total_props = sro._inner
    total_props = clean_props(total_props)
    
    # - work out the type of object
    obj_type = sro.type
    # - get the object-specific typeql names, sighting or relationship
    obj_tql = dispatch_stix[obj_type]
    # - add on the generic sro properties
    obj_tql.update(sro_base_typeql_dict)
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
        for record in stix_rel_roles:
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

#---------------------------------------------------
# 1.3) SCO Object Method to convert a Python object --> typeql string
#                 -   
#--------------------------------------------------
def sco_to_typeql(sco, import_type='stix21'):
    # 1.) get configuration parameters
    # - variable for use in typeql statements
    sco_var = '$' + sco.type
    # - list of property names that have values
    total_props = sco._inner
    total_props = clean_props(total_props)
    #print(properties)
    # - work out the type of object
    obj_type = sco.type
    # - get the object-specific typeql names, sighting or relationship
    obj_tql = dispatch_stix[obj_type]
    # - add on the generic sro properties
    obj_tql.update(sco_base_typeql_dict)
    #initialise the typeql insert statement
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
    type_ql += ";\n" +  type_ql_props + "\n\n"
    
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
  
#---------------------------------------------------
# 1.4) Meta Object Method to convert a Python object --> typeql string
#                 -  marking definitions, statement, colour and Mitre copyright
#--------------------------------------------------
  
  
def marking_definition_to_typeql(stix_object, import_type="stix21"):
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
  
#---------------------------------------------------
# 1.5) Sub Object Methods for adding common standard properties
#                -  e.g. stix-type, stix-id, name, description etc.
#--------------------------------------------------

def clean_props(total_props):
    # remove the properties that are mistakes
    
    return total_props

  
def add_property_to_typeql(prop, obj_tql, obj, prop_var_list):
    type_ql = type_ql_props = ''
    tql_prop_name = obj_tql[prop]
    # if property is defanged, summary or revoked, and the value is false, then don't add it to typedb description
    if prop == "defanged" and obj.defanged == False:
        return type_ql, type_ql_props, prop_var_list
    elif prop == "revoked" and obj.revoked == False:
        return type_ql, type_ql_props, prop_var_list
    elif prop == "summary" and obj.summary == False:
        return type_ql, type_ql_props, prop_var_list
    
    # or else add the property to the typeql statement
    if isinstance(obj[prop], list):
        # if the property is a list, add each item to the typeql statement
        for i, instance in enumerate(obj[prop]):
            prop_var_dict={}
            # import statements for each of the list items
            prop_var = '$' + prop + str(i)
            type_ql += ',\n has ' + tql_prop_name + ' ' + prop_var 
            type_ql_props += '\n ' + prop_var + ' '  + val_tql(instance) + ';'
            prop_var_dict["prop_var"] = prop_var
            prop_var_dict["prop"] = prop
            prop_var_dict["index"] = i
            prop_var_list.append(prop_var_dict)
    else:
        prop_var_dict={}
        # import statements for a single value
        prop_var = '$' + tql_prop_name
        type_ql += ',\n has ' + tql_prop_name + ' ' + prop_var 
        type_ql_props += '\n ' + prop_var + ' '  + val_tql(obj[prop]) + ';'
        prop_var_dict["prop_var"] = prop_var
        prop_var_dict["prop"] = prop
        prop_var_dict["index"] = -1
        prop_var_list.append(prop_var_dict)  
        
    return type_ql, type_ql_props, prop_var_list
  

#---------------------------------------------------
# 1.6) Sub Object Methods for adding embedded structures
#                -  e.g. hasehs, kill-chain-phases, created_by, external_references, object_marking_refs etc.
#--------------------------------------------------
# Giant Switch statement to add the embedded relations to the typeql statement

def add_relation_to_typeql(rel, obj, obj_var, prop_var_list=[], inc=-1):
    if rel == "granular_markings":
        match, insert = granular_markings( rel, obj[rel], obj_var, prop_var_list)
    
    # hashes type
    elif (rel == "hashes"
          or rel == "file_header_hashes"):
        match, insert = hashes( rel, obj[rel], obj_var)
    

    # insert key value store
    elif (rel == "additional_header_fields"
          or rel == "document_info_dict"
          or rel == "exif_tags"
          or rel == "ipfix"
          or rel == "request_header"
          or rel == "options"
          or rel == "environment_variables"
          or rel == "startup_info"):
        match, insert = key_value_store( rel, obj[rel], obj_var)
    
    # insert list of object relation
    elif (rel == "body_multipart"
          or rel == "external_references"
          or rel == "kill_chain_phases"
          or rel == "sections"
          or rel == "alternate_data_streams"
          or rel == "values"):
        match, insert = list_of_object( rel, obj[rel], obj_var)
    
    # insert embedded relations based on stix-id
    elif (rel == "object_refs"
          or rel == "created_by_ref"
          or rel == "object_marking_refs"
          or rel == "sample_refs"
          or rel == "host_vm_ref"
          or rel == "operating_system_ref"
          or rel == "installed_software_refs"
          or rel == "analysis_sco_refs"
          or rel == "sample_ref"
          or rel == "contains_refs"
          or rel == "resolves_to_refs"
          or rel == "belongs_to_ref"
          or rel == "belongs_to_refs"
          or rel == "raw_email_ref"
          or rel == "from_ref"
          or rel == "sender_ref"
          or rel == "to_refs"
          or rel == "cc_refs"
          or rel == "bcc_refs"
          or rel == "body_raw_ref"
          or rel == "raw_email_ref"
          or rel == "content_ref"
          or rel == "parent_directory_ref"
          or rel == "src_ref"
          or rel == "dst_ref"
          or rel == "src_payload_ref"
          or rel == "dst_payload_ref"
          or rel == "encapsulates_refs"
          or rel == "encapsulated_by_ref"
          or rel == "message_body_data_ref"
          or rel == "opened_connection_refs"
          or rel == "creator_user_ref"
          or rel == "image_ref"
          or rel == "parent_ref"
          or rel == "child_refs"
          or rel == "service_dll_refs"): 
        match, insert = embedded_relation( rel, obj[rel], obj_var, inc)
    
    # insert plain sub-object with relation
    elif (rel == "x509_v3_extensions"
          or rel == "optional_header"):
        match, insert = load_object( rel, obj[rel], obj_var)
        
    # insert  SCO Extensions here, a possible dict of sub-objects
    elif rel == "extensions":
        match, insert = extensions( rel, obj[rel], obj_var)
    
    # ignore the following relations as they are already processed, for Relationships, Sightings and Extensions
    elif (rel == "sighting_of_ref" 
          or rel == "observed_data_refs" 
          or rel == "where_sighted_refs"
          or rel == "source_ref" 
          or rel == "target_ref"):
        match = insert = ''
    
    else:
        logger.error(f'relation type not known, rel -> {rel}')
        match = insert = ""
        
    return match, insert
  


#---------------------------------------------------
# Methods for adding the embedded structures to the typeql statement
#--------------------------------------------------
# generic methods
def extensions(prop_name, prop_dict, parent_var):
    match = insert = ''
    # for each key in the dict (extension type)
    #logger.debug('--------------------- extensions ----------------------------')
    for ext_type in prop_dict:
        for ext_type_ql in ext_typeql_dict_list:
            if ext_type == ext_type_ql["stix"]:
                match2, insert2 = load_object(ext_type, prop_dict[ext_type], parent_var)
                match = match + match2
                insert = insert + insert2
                break
        
    return match, insert



def load_object(prop_name, prop_dict, parent_var):
    match = insert = type_ql = type_ql_props = ''
    # as long as it is predefined, load the object
    #logger.debug('------------------- load object ------------------------------')
    for prop_type in ext_typeql_dict_list:
        if prop_name == prop_type["stix"]:
            tot_prop_list = [tot for tot in prop_dict.keys()]
            obj_tql = prop_type["dict"]
            obj_var = '$' + prop_type["object"]
            reln = prop_type["relation"]
            rel_var = '$' + reln
            rel_owner = prop_type["owner"]
            rel_pointed_to = prop_type["pointed-to"]
            type_ql += ' ' + obj_var + ' isa ' + prop_type["object"]
            # Split them into properties and relations
            properties, relations = split_on_activity_type(tot_prop_list, obj_tql)     
            prop_var_list = []
            for prop in properties:
                # split off for properties processing
                type_ql2, type_ql_props2, prop_var_list = add_property_to_typeql(prop, obj_tql, prop_dict, prop_var_list)
                # then add them all together
                type_ql += type_ql2
                type_ql_props += type_ql_props2        
            # add a terminator on the end of the insert statement
            type_ql += ";\n" +  type_ql_props + "\n\n"
            
            # add each of the relations to the match and insert statements
            for rel in relations:        
                # split off for relation processing
                match2, insert2 = add_relation_to_typeql(rel, prop_dict, obj_var, prop_var_list)
                # then add it back together    
                match = match +  match2
                insert = insert + "\n" + insert2                   
                
            # finally, connect the local object to the parent object
            type_ql += ' ' + rel_var + ' (' + rel_owner + ':' + parent_var 
            type_ql += ', ' + rel_pointed_to + ':' + obj_var + ')'
            type_ql += ' isa ' + reln + ';\n'
            break            
        
    insert =  type_ql + "\n" + insert
    return match, insert




def list_of_object(prop_name, prop_value_list, parent_var):
    for config in list_of_object_typeql:
        if config["name"] == prop_name:
            rel_typeql = config["typeql"]
            obj_props_tql = config["typeql_props"]
            role_owner = config["owner"]
            role_pointed = config["pointed_to"]
            typeql_obj = config["object"]
            break
        
    lod_list = []
    match = rel_insert = rel_match = insert = ''
    for i, dict_instance in enumerate(prop_value_list):
        lod_var = '$' + typeql_obj + str(i)
        lod_list.append(lod_var)
        insert += lod_var + ' isa ' + typeql_obj
        for key in dict_instance:
            typeql_prop = obj_props_tql[key]
            if typeql_prop == '':
                rel_match2, rel_insert2 = add_relation_to_typeql(key, dict_instance, lod_var, [], i)    
                rel_insert += rel_insert2
                rel_match += rel_match2                            
            else:
                insert += ',\n has ' + typeql_prop + ' ' + val_tql(dict_instance[key])
        insert += ';\n'
        
    insert += '\n $' + rel_typeql + ' (' + role_owner + ':' + parent_var 
    for lod_var in lod_list:
        insert +=  ', ' + role_pointed + ':' + lod_var
        
    insert += ') isa ' + rel_typeql  + ';\n' + rel_insert
    match += rel_match
    return match, insert

def key_value_store( prop, prop_value_dict, obj_var):
    for config in key_value_typeql_list:
        if config["name"] == prop:
            rel_typeql = config["typeql"]
            role_owner = config["owner"]
            role_pointed = config["pointed_to"]
            d_key = config["key"]
            d_value = config["value"]
            break
    
    match = ''
    insert = '\n'
    field_var_list = []
    for i, key in enumerate(prop_value_dict):
        a_value = prop_value_dict[key]
        key_var = ' $' + d_key + str(i)
        field_var_list.append(key_var)
        insert += key_var + ' isa ' + d_key + '; ' + key_var + ' "' + key + '";\n'
        if isinstance(a_value, list):
            for j, n in enumerate(a_value):
                value_var = ' $' + d_value + str(j)
                insert += key_var + ' ' + 'has ' + d_value +  ' "' + str(n) + '";\n'
        else:
            value_var = ' $' + d_value + str(i)
            insert += key_var + ' ' + 'has ' + d_value + ' "' +  str(a_value) + '";\n'
    
    insert += ' $' + rel_typeql + ' (' + role_owner + ':' + obj_var
    for var in field_var_list:
        insert += ', ' + role_pointed + ':' + var
    insert += ') isa ' + rel_typeql + ';\n\n'
    return match, insert
  

# specific methods
def hashes(prop_name, prop_dict, parent_var):
    match = insert = ''
    hash_var_list = []
    for i, key in enumerate(prop_dict):
        hash_var = '$hash' + str(i)
        hash_var_list.append(hash_var)
        if key in hash_typeql_dict:
            insert += ' ' + hash_var + ' isa ' + hash_typeql_dict[key] + ', has hash-value ' + val_tql(prop_dict[key]) + ';\n'        
        else:
          logger.error(f'Unknown hash type {key}')
          
    # insert the hash objects into the hashes relation with the parent object
    insert += '\n $hash_rel (owner:' + parent_var
    for hash_var in hash_var_list:
         insert += ', pointed-to:' + hash_var 
         
    insert +=  ') isa hashes;\n'    
    return match, insert
  

def granular_markings(prop_name, prop_value_List, parent_var, prop_var_list):
    match = insert = ''
    for i, prop_dict in enumerate(prop_value_List):
        # setup and match in the marking, based on its id
        m_id = prop_dict['marking_ref']
        m_var = '$marking' + str(i)
        g_var = '$granular' + str(i)
        match += ' ' + m_var + ' isa marking-definition, has stix-id ' + '"' + m_id + '";\n'
        insert += ' ' + g_var + ' (marking:' + m_var + ', object:' + parent_var
        prop_list = prop_dict['selectors']
        for selector in prop_list:
            selector_var = get_selector_var(selector, prop_var_list)
            insert += ', marked:' + selector_var
            
        insert += ') isa granular-marking;\n'
    
    return match, insert
  
def get_selector_var(selector, prop_var_list):
    if selector[-1] == ']':
        text = selector.split(".")
        selector = text[0]
        index = int(text[1][1])
    else:
        selector = selector
        index = -1
        
    #logger.debug(f'selector after processing -> {selector}, index after procesing -> {index}')
    for prop_var_dict in prop_var_list:
        if selector == prop_var_dict['prop'] and index == prop_var_dict['index']:
            selector_var = prop_var_dict['prop_var']
            break
        
    return selector_var



#---------------------------------------------------
#        EMBEDDED RELATION METHODS
#---------------------------------------------------
# object_refs
# sample_refs
# sample_ref
# host_vm_ref
# operating_system_ref
# installed_software_refs
# analysis_sco_refs
# etc.

def embedded_relation(prop, prop_value, obj_var, inc):
    for ex in embedded_relations_typeql:
      if ex["rel"] == prop:
        owner = ex["owner"]
        pointed_to = ex["pointed-to"]
        relation = ex["typeql"]
        break
    
    prop_var_list = []
    match = ''
    if inc == -1:
        inc_add = ''
    else:
        inc_add = str(inc)
    # if the prop_value is a list, then match in each item
    if isinstance(prop_value, list):        
        for i, prop_v in enumerate(prop_value):
            prop_type = prop_v.split('--')[0]
            if prop_type == 'relationship':
                prop_type = 'stix-core-relationship'
            prop_var = '$' + prop_type + str(i) + inc_add
            prop_var_list.append(prop_var)
            match += ' ' + prop_var + ' isa ' + prop_type + ', has stix-id ' + '"' + prop_v + '";\n'
    # else, match in the single prop_value
    else:
        prop_type = prop_value.split('--')[0]
        if prop_type == 'relationship':
            prop_type = 'stix-core-relationship'
        prop_var = '$' + prop_type  + inc_add
        prop_var_list.append(prop_var)
        match += ' ' + prop_var + ' isa ' + prop_type + ', has stix-id ' + '"' + prop_value + '";\n'
  
    # Then setup and insert the relation
    insert = '\n $' + relation + inc_add + ' (' + owner + ':' + obj_var
    for prop_var in prop_var_list:
        insert += ', ' + pointed_to + ':' + prop_var
    insert += ') isa ' + relation + ';\n'
    return match, insert


def get_embedded_match(source_id, i=1):
    source_type = source_id.split('--')[0]
    source_var = '$' + source_type + str(i)
    if source_type == 'relationship':
        source_type = 'stix-core-relationship'
    match = f' {source_var} isa {source_type}, has stix-id "{source_id}";\n'
    return source_var, match

def get_full_object_match(source_id):
    source_var, match = get_embedded_match(source_id)
    match += source_var + ' has $properties;\n'
    # match += '$embedded (owner:' + source_var + ', pointed-to:$point ) isa embedded;\n'
    return source_var, match
    

#---------------------------------------------------
# 1.7) Helper Methods for 
#           - converting a Python value --> typeql string
#           - splitting a list of total properties into properties and relations
#---------------------------------------------------
def val_tql(val):
    if isinstance(val, str):
        replaced_val = val.replace('"', "'")
        replaced_val2 = replaced_val.replace('\\', '\\\\')
        return '"' + replaced_val2 + '"'
    elif isinstance(val, bool):
        return str(val).lower()
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    elif isinstance(val, datetime.datetime):
        return  str(val.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]) 
    else:
        return logger.error(f'value  not supported: {val}')
      
def split_on_activity_type(total_props, obj_tql):
    prop_list = []
    rel_list = []
    for prop in total_props:
      tql_prop_name = obj_tql[prop]
      
      if tql_prop_name == "":
        rel_list.append(prop)
        #logger.debug(f'Im a rel --> {prop},        tql --> {tql_prop_name}')
      else:
        prop_list.append(prop)
        #logger.debug(f'Im a prop --> {prop},        tql --> {tql_prop_name}')
        
    return prop_list, rel_list
        


##################################################
# 2. Dispatch Dicts to convert between:
#      - Stix2 Object Property Name --> TypeQL Name
#      - Stix 2 Object Type --> Dict Name
###################################################

#---------------------------------------------------
# 2.1) Stix Domain Object Dicts
#---------------------------------------------------
sdo_typeql_dict = {
  "type" :  "stix-type",
  "spec_version" : "spec-version",
  "id"  : "stix-id",
  "created_by_ref"  : "",
  "created"  : "created",
  "modified" : "modified",
  "revoked"  : "revoked",
  "labels"  : "labels",
  "confidence"  : "confidence",
  "lang"  : "langs",
  "external_references"  : "",
  "object_marking_refs"  : "",
  "granular_markings"  : "",
  "extensions"  : ""
}

attack_pattern_typeql_dict = {
  "name": "name",
  "description": "description",
  "aliases": "aliases",
  "kill_chain_phases": ""
}

campaign_typeql_dict = {
  "name": "name",
  "description": "description",
  "aliases": "aliases",
  "first_seen": "first-seen",
  "last_seen": "last-seen",
  "objective": "objective"
}

grouping_typeql_dict = {
  "name": "name",
  "description": "description",
  "context": "context",
  "object_refs": ""
}

course_of_action_typeql_dict = {
  "name": "name",
  "description": "description",	
  "action": "action"
}

identity_typeql_dict = {
  "name" :  "name",
  "description" :  "description",
  "roles" :  "stix-role",
  "identity_class" :  "identity-class",
  "sectors" :  "sector",
  "contact_information" :  "contact-information"
}

incident_typeql_dict = {
  "name": "name",
  "description": "description",
}

indicator_typeql_dict = {
  "name": "name",
  "description": "description",
  "pattern_version": "pattern-version",
  "indicator_types": "indicator-type",
  "pattern": "pattern",
  "pattern_type": "pattern-type",
  "valid_from": "valid-from",
  "valid_until": "valid-until",
  "kill_chain_phases": ""
}

infrastructure_typeql_dict = {
  "name": "name",
  "description": "description",
  "infrastructure_types": "infrastructure-types",
  "aliases": "aliases",
  "kill_chain_phases": "",
  "first_seen": "first-seen",
  "last_seen": "last-seen"
}

intrusion_set_typeql_dict = {
  "name": "name",
  "description": "description",
  "aliases": "aliases",
  "first_seen": "first-seen",
  "last_seen": "last-seen",
  "goals": "goals",
  "resource_level": "resource-level",
  "primary_motivation": "primary-motivation",
  "secondary_motivations": "secondary-motivations"
}

location_typeql_dict = {
  "name": "name",
  "description": "description",
  "latitude": "latitude",
  "longitude": "longitude",
  "precision": "precision",
  "region": "region",
  "country": "country",
  "administrative_area": "administrative-area",
  "city": "city",
  "street_address": "street-address",
  "postal_code": "postal-code"
}

malware_typeql_dict = {
  "name": "name",	
  "description": "description",
  "malware_types": "malware-types",
  "is_family": "is-family",
  "aliases": "aliases",
  "kill_chain_phases": "",
  "first_seen": "first-seen",
  "last_seen": "last-seen",
  "operating_system_refs": "",
  "architecture_execution_envs": "architecture-execution-envs",
  "implementation_languages": "implementation-languages",
  "capabilities": "capabilities",
  "sample_refs": ""
}

malware_analysis_typeql_dict = {
  "product": "product",
  "version": "version",
  "host_vm_ref": "",
  "operating_system_ref": "",
  "installed_software_refs": "",
  "configuration_version": "configuration-version",
  "modules": "modules",
  "analysis_engine_version": "analysis-engine-version",
  "analysis_definition_version": "analysis-definition-version",
  "submitted": "submitted",
  "analysis_started": "analysis-started",
  "analysis_ended": "analysis-ended",
  "result_name": "result-name",
  "result": "result",
  "analysis_sco_refs": "",
  "sample_ref": ""
}

note_type_dict = {
  "abstract": "abstract",
  "content": "content",
  "authors": "authors",
  "object_refs": ""
}

observed_data_typeql_dict = {
  "first_observed": "first-observed",
  "last_observed": "last-observed",
  "number_observed": "number-observed",
  "object_refs": ""
}

opinion_typeql_dict = {
  "explanation": "explanation",
  "authors": "authors",
  "opinion": "opinion-enum",
  "object_refs": ""
}

report_typeql_dict = {
  "name": "name",
  "description": "description",
  "report_types": "report-type",
  "published": "published",
  "object_refs": ""
}

threat_actor_typeql_dict = {        
  "name"  : "name",
  "description"  : "description",
  "threat_actor_types"  : "threat-actor-type",
  "aliases"  : "aliases",
  "first_seen"  : "first-seen",
  "last_seen"  : "last-seen",
  "roles"  : "stix-role",
  "goals"  : "goals",
  "sophistication"  : "sophistication",
  "resource_level"  : "resource-level",
  "primary_motivation"  : "primary-motivation",
  "secondary_motivations"  : "secondary-motivations",
  "personal_motivations"  : "personal-motivations"        
}

tool_typeql_dict = {
  "name": "name",
  "description": "description",
  "tool_types": "tool-type",
  "aliases": "aliases",
  "kill_chain_phases": "",
  "tool_version": "tool-version"
}

vulnerability_typeql_dict = {
  "name": "name",
  "description": "description"
}

kill_chain_phases_typeql_dict = {
  "kill_chain_name": "kill-chain-name",
  "phase_name": "phase-name"
  
}


#---------------------------------------------------
# 2.2) Stix Cyber Observable Object Dicts
#---------------------------------------------------

sco_base_typeql_dict = {
  "type" :  "stix-type",
  "spec_version" : "spec-version",
  "id"  : "stix-id",
  "created_by_ref"  : "",
  "revoked"  : "revoked",
  "labels"  : "labels",
  "confidence"  : "confidence",
  "lang"  : "langs",
  "external_references"  : "",
  "object_marking_refs"  : "",
  "granular_markings"  : "",
  "defanged"  : "defanged",
  "extensions"  : ""
}

artifact_typeql_dict = {
  "mime_type": "mime-type",
  "payload_bin": "payload-bin",
  "url": "url-link",
  "hashes": "",
  "encryption_algorithm": "encryption-algorithm",
  "decryption_key": "decryption-key"
}

autonomous_system_typeql_dict = {
    "number": "number",
    "name": "name",
    "rir": "rir"
}

directory_typeql_dict = {
    "path": "path",
    "path_enc": "path-enc",
    "ctime": "ctime",
    "mtime": "mtime",
    "atime": "atime",
    "contains_refs": "",
}


domain_name_typeql_dict = {
    "value": "stix-value",
    "resolves_to_refs": ""
}

email_addr_typeql_dict = {
    "value": "stix-value",
    "display_name": "display-name",
    "belongs_to_ref": ""
}

email_message_typeql_dict = {
    "is_multipart": "is-multipart",
    "date": "date",
    "content_type": "content-type",
    "from_ref": "",
    "sender_ref": "",
    "to_refs": "",
    "cc_refs": "",
    "bcc_refs": "",
    "message_id": "message-id",
    "subject": "subject",
    "received_lines": "received-lines",
    "additional_header_fields": "",
    "body": "body",
    "body_multipart": "",
    "raw_email_ref": ""
}

file_typeql_dict = {
    "hashes": "",
    "size": "size",
    "name": "name",
    "name_enc": "name-enc",
    "magic_number_hex": "magic-number-hex",
    "mime_type": "mime-type",
    "ctime": "ctime",
    "dtime": "dtime",
    "atime": "atime",
    "parent_directory_ref": "",
    "contains_refs": "",
    "content_ref": ""
}

ipv4_addr_typeql_dict = {
    "value": "stix-value",
    "resolves_to_refs": "",
    "belongs_to_refs": ""
}

ipv6_addr_typeql_dict = {
    "value": "stix-value",
    "resolves_to_refs": "",
    "belongs_to_refs": ""
}

mac_addr_typeql_dict = {
    "value": "stix-value"
}

mutex_typeql_dict = {
    "name": "name"
}

network_traffic_typeql_dict = {
    "start": "start",
    "end": "end",
    "is_active": "is-active",
    "src_ref": "",
    "dst_ref": "",
    "src_port": "src-port",
    "dst_port": "dst-port",
    "protocols": "protocols",
    "src_byte_count": "src-byte-count",
    "dst_byte_count": "dst-byte-count",
    "src_packets": "src-packets",
    "dst_packets": "dst-packets",
    "ipfix": "",
    "src_payload_ref": "",
    "dst_payload_ref": "",
    "encapsulates_refs": "",
    "encapsulated_by_ref": ""    
}

process_typeql_dict = {
    "is_hidden": "is-hidden",
    "pid": "pid",
    "created_time": "created-time",
    "cwd": "cwd",
    "command_line": "command-line",
    "environment_variables": "",
    "opened_connection_refs": "",
    "creator_user_ref": "",
    "image_ref": "",
    "parent_ref": "",
    "child_refs": ""   
    
}

software_typeql_dict = {
    "name": "name",
    "cpe": "cpe",
    "swid": "swid",
    "languages": "language",
    "vendor": "vendor",
    "version": "version"
}


url_typeql_dict = {
    "value": "stix-value"
}

user_account_typeql_dict = {
    "user_id": "user-id",
    "credential": "credential",
    "account_login": "account-login",
    "account_type": "account-type",
    "display_name": "display-name",
    "is_service_account": "is-service-account",
    "is_privileged": "is-privileged",
    "can_escalate_privs": "can-escalate-privs",
    "is_disabled": "is-disabled",
    "account_created": "account-created",
    "account_expires": "account-expires",
    "credential_last_changed": "credential-last-changed",
    "account_first_login": "account-first-login",
    "account_last_login": "account-last-login"
}

windows_registry_key_typeql_dict = {
    "key": "attribute-key",
    "values": "",
    "modified_time": "modified-time",
    "creator_user_ref": "",
    "number_of_subkeys": "number-subkeys"
}

windows_registry_value_typeql_dict = {
    "name": "name",
    "data": "data",
    "data_type": "data-type"
}

x509_certificate_typeql_dict = {
    "is_self_signed": "is-self-signed",
    "hashes": "",
    "version": "version",
    "serial_number": "serial-number",
    "signature_algorithm": "signature-algorithm",
    "issuer": "issuer",
    "validity_not_before": "validity-not-before",
    "validity_not_after": "validity-not-after",
    "subject": "subject",
    "subject_public_key_algorithm": "subject-public-key-algorithm",
    "subject_public_key_modulus": "subject-public-key-modulus",
    "subject_public_key_exponent": "subject-public-key-exponent",
    "x509_v3_extensions": ""
}




#---------------------------------------------------
# 2.2b) SCO Extensions and Similar
#---------------------------------------------------

email_mime_part_typeql_dict = {
    "body": "body",
    "content_type": "content-type",
    "content_disposition": "content-disposition",
    "body_raw_ref": ""
}

archive_ext_typeql_dict = {
    "comment": "comment",
    "contains_refs": ""
}

ntfs_ext_typeql_dict = {
    "sid": "sid",
    "alternate_data_streams": ""
}

alternate_data_stream_ext_typeql_dict = {
    "name": "name",
    "size": "size",
    "hashes": ""
}

pdf_ext_typeql_dict = {
    "version": "version",
    "is_optimized": "is-optimized",
    "document_info_dict": "",
    "pdfid0": "pdfid0",
    "pdfid1": "pdfid1"
}

raster_image_ext_typeql_dict = {
    "image_height": "image-height",
    "image_width": "image-width",
    "exif_tags": "",
    "bits_per_pixel": "bits-per-pixel"
}

windows_pebinary_ext_typeql_dict = {
    "pe_type": "pe-type",
    "imphash": "imphash",
    "machine_hex": "machine-hex",
    "number_of_sections": "number-of-sections",
    "time_date_stamp": "time-date-stamp",
    "pointer_to_symbol_table_hex": "pointer-to-symbol-table-hex",
    "number_of_symbols": "number-of-symbols",
    "size_of_optional_header": "size-of-optional-header",
    "characteristics_hex": "characteristics-hex",
    "file_header_hashes": "",
    "optional_header": "",
    "sections": ""
}

windows_optional_header_ext_typeql_dict = {
    "magic_hex": "magic-hex",
    "major_linker_version": "major-linker-version",
    "minor_linker_version": "minor-linker-version",
    "size_of_code": "size-of-code",
    "size_of_initialized_data": "size-of-initialized-data",
    "size_of_uninitialized_data": "size-of-uninitialized-data",
    "address_of_entry_point": "address-of-entry-point",
    "base_of_code": "base-of-code",
    "base_of_data": "base-of-data",
    "image_base": "image-base",
    "section_alignment": "section-alignment",
    "file_alignment": "file-alignment",
    "major_os_version": "major-os-version",
    "minor_os_version": "minor-os-version",
    "major_image_version": "major-image-version",
    "minor_image_version": "minor-image-version",
    "major_subsystem_version": "major-subsystem-version",
    "minor_subsystem_version": "minor-subsystem-version",
    "win32_version_value_hex": "win32-version-value-hex",
    "size_of_image": "size-of-image",
    "size_of_headers": "size-of-headers",
    "checksum_hex": "checksum-hex",
    "subsystem_hex": "subsystem-hex",
    "dll_characteristics_hex": "dll-characteristics-hex",
    "size_of_stack_reserve": "size-of-stack-reserve",
    "size_of_stack_commit": "size-of-stack-commit",
    "size_of_heap_reserve": "size-of-heap-reserve",
    "size_of_heap_commit": "size-of-heap-commit",
    "loader_flags_hex": "loader-flags-hex",
    "number_of_rva_and_sizes": "number-of-rva-and-sizes",
    "hashes": ""
}

windows_pe_section_ext_typeql_dict = {
    "name": "name",
    "size": "size",
    "entropy": "entropy",
    "hashes": ""
}

HTTP_request_ext_typeql_dict = {
    "request_method": "request-method",
    "request_value": "request-value",
    "request_version": "request-version",
    "request_header": "",
    "message_body_length": "message-body-length",
    "message_body_data_ref": ""
}

icmp_ext_typeql_dict = {
    "icmp_type_hex": "icmp-type-hex",
    "icmp_code_hex": "icmp-code-hex"
}

socket_ext_typeql_dict = {
    "address_family": "address-family",
    "is_blocking": "is-blocking",
    "is_listening": "is-listening",
    "options": "",
    "socket_type": "socket-type",
    "socket_description": "socket-description",
    "socket_handle": "socket-handle"
}


tcp_ext_typeql_dict = {
    "src_flags_hex": "src-flags-hex",
    "dst_flags_hex": "dst-flags-hex"
}

windows_process_ext_typeql_dict = {
    "aslr_enabled": "aslr-enabled",
    "dep_enabled": "dep-enabled",
    "priority": "priority",
    "owner_sid": "owner-sid",
    "window_title": "window-title",
    "startup_info": "",
    "integrity_level": "integrity-level"
}

windows_service_ext_typeql_dict = {
    "service_name": "service-name",
    "descriptions": "description",
    "display_name": "display-name",
    "group_name": "group-name",
    "start_type": "start-type",
    "service_dll_refs": "",
    "service_type": "service-type",
    "service_status": "service-status"
}

unix_account_ext_typeql_dict = {
    "gid": "gid",
    "groups": "unix-group",
    "home_dir": "home-dir",
    "shell": "shell"
}

x509_v3_ext_typeql_dict = {
    "basic_constraints": "basic-constraints",
    "name_constraints": "name-constraints",
    "policy_constraints": "policy-constraints",
    "key_usage": "key-usage",
    "extended_key_usage": "extended-key-usage",
    "subject_key_identifier": "subject-key-identifier",
    "authority_key_identifier": "authority-key-identifier",
    "subject_alternative_name": "subject-alternative-name",
    "issuer_alternative_name": "issuer-alternative-name",
    "subject_directory_attributes": "subject-directory-attributes",
    "crl_distribution_points": "crl-distribution-points",
    "inhibit_any_policy": "inhibit-any-policy",
    "private_key_usage_period_not_before": "private-key-usage-period-not-before",
    "private_key_usage_period_not_after": "private-key-usage-period-not-after",
    "certificate_policies": "certificate-policies",
    "policy mapping": "policy-mapping"
}



ext_typeql_dict_list = [
    {   "stix": "archive-ext",
        "dict": archive_ext_typeql_dict,
        "object": "archive-ext",
        "relation": "archive-extension", 
        "owner": "file",
        "pointed-to": "an-archive"},
    {   "stix": "ntfs-ext",
        "dict": ntfs_ext_typeql_dict,
        "object": "ntfs-ext",
        "relation": "ntfs-extension", 
        "owner": "file",
        "pointed-to": "ntfs"},
    {   "stix": "alternate_data_streams",
        "dict": alternate_data_stream_ext_typeql_dict,
        "object": "alternate-data-stream",
        "relation": "alt-data-streams", 
        "owner": "ntfs-ext",
        "pointed-to": "alt-data-stream"},
    {   "stix": "pdf-ext",
        "dict": pdf_ext_typeql_dict,
        "object": "pdf-ext",
        "relation": "pdf-extension", 
        "owner": "file",
        "pointed-to": "pdf"},
    {   "stix": "raster-image-ext",
        "dict": raster_image_ext_typeql_dict,
        "object": "raster-image-ext",
        "relation": "raster-image-extension", 
        "owner": "file",
        "pointed-to": "image"},
    {   "stix": "windows-pebinary-ext",
        "dict": windows_pebinary_ext_typeql_dict,
        "object": "windows-pebinary-ext",
        "relation": "windows-pebinary-extension", 
        "owner": "file",
        "pointed-to": "pebinary"},
    {   "stix": "windows-pe-section-type",
        "dict": windows_pe_section_ext_typeql_dict,
        "object": "windows-pe-section",
        "relation": "sections", 
        "owner": "pebinary",
        "pointed-to": "pe-section"},
    {   "stix": "http-request-ext",
        "dict": HTTP_request_ext_typeql_dict,
        "object": "http-request-ext",
        "relation": "http-request-extension", 
        "owner": "traffic",
        "pointed-to": "request"},
    {   "stix": "icmp-ext",
        "dict": icmp_ext_typeql_dict,
        "object": "icmp-ext",
        "relation": "icmp-extension", 
        "owner": "traffic",
        "pointed-to": "icmp"},
    {   "stix": "socket-ext",
        "dict": socket_ext_typeql_dict,
        "object": "socket-ext",
        "relation": "socket-extension", 
        "owner": "traffic",
        "pointed-to": "socket"},
    {   "stix": "tcp-ext",
        "dict": tcp_ext_typeql_dict,
        "object": "tcp-ext",
        "relation": "tcp-extension", 
        "owner": "traffic",
        "pointed-to": "tcp"},
    {   "stix": "windows-process-ext",
        "dict": windows_process_ext_typeql_dict,
        "object": "windows-process-ext",
        "relation": "windows-process-extension", 
        "owner": "process",
        "pointed-to": "win-process"},
    {   "stix": "windows-service-ext",
        "dict": windows_service_ext_typeql_dict,
        "object": "windows-service-ext",
        "relation": "windows-service-extension", 
        "owner": "process",
        "pointed-to": "win-service"},
    {   "stix": "unix-account-ext",
        "dict": unix_account_ext_typeql_dict,
        "object": "unix-account-ext",
        "relation": "unix-account-extension", 
        "owner": "account",
        "pointed-to": "unix"},
    {   "stix": "x509_v3_extensions",
        "dict": x509_v3_ext_typeql_dict,
        "object": "x509-v3-extension",
        "relation": "v3-extensions", 
        "owner": "cert",
        "pointed-to": "v3-extension"},
    {   "stix": "optional_header",
        "dict": windows_optional_header_ext_typeql_dict,
        "object": "windows-pe-optional-header-type",
        "relation": "optional-headers", 
        "owner": "pebinary",
        "pointed-to": "optional-header"}
]
  
  
  

#---------------------------------------------------
# 2.3) Marking Definition
#---------------------------------------------------

marking_typeql_dict = {
  "type": "stix-type",
  "id": "stix-id",
  "spec_version": "spec-version",
  "created": "created",
  "name": "name",
  "statement": "statement"
  
}

ext_ref_typeql_dict = {
  "source_name": "source-name",
  "description": "description",
  "url": "url-link",
  "hashes": "",
  "external_id": "external-id"	
}

hash_typeql_dict = {
  "MD5": "md-5",
  "SHA-1": "sha-1",
  "SHA-256": "sha-256",
  "SHA-512": "sha-512",
  "SHA3-256": "sha3-256",
  "SHA3-512": "sha3-512",
  "SSDEEP": "ssdeep",
  "TLSH": "tlsh"
}



#---------------------------------------------------
# 2.4) Stix type_ql_relationhip Object Dict and TypeQL Roles List of Dicts
#---------------------------------------------------

sro_base_typeql_dict = {
  "type" :  "stix-type",
  "spec_version" :  "spec-version",
  "id" :  "stix-id",
  "created_by_ref" :  "",
  "created" :  "created",
  "modified" :  "modified",
  "revoked" :  "revoked",
  "labels" :  "labels",
  "confidence" :  "confidence",
  "lang" :  "langs",
  "external_references" :  "",
  "object_marking_refs" :  "",
  "granular_markings" :  "",
  "extensions" :  ""
}

relationship_typeql_dict = {        
  "relationship_type" :  "relationship-type",
  "description" :  "description",
  "source_ref" :  "",
  "target_ref" :  "",
  "start_time" :  "start-time",
  "stop_time" :  "stop-time"        
}

sighting_typeql_dict = {
  "description" :  "description",
  "first_seen" :  "first-seen",
  "last_seen" :  "last-seen",
  "count" :  "count",
  "sighting_of_ref" :  "",
  "observed_data_refs" :  "",
  "where_sighted_refs" :  "",
  "summary" :  "summary"
}
    

stix_rel_roles = [
 {   "stix": "delivers",    "typeql": "delivers",    "source": "delivering",    "target": "delivered" }, 
 {   "stix": "targets",    "typeql": "targets",   "source": "targetter",   "target": "targetted" }, 
 {   "stix": "uses",   "typeql": "uses",   "source": "used-by",   "target": "used" }, 
 {   "stix": "attributed-to",   "typeql": "attributed-to",   "source": "result",   "target": "fault-of" }, 
 {   "stix": "compromises",   "typeql": "compromises",   "source": "compromising",   "target": "compromised" }, 
 {   "stix": "originates-from", "typeql": "originates-from",   "source": "originating",   "target": "originated-from" }, 
 {   "stix": "investigates",   "typeql": "investigates",   "source": "investigating",   "target": "investigated" }, 
 {   "stix": "mitigates",   "typeql": "mitigates",   "source": "mitigator",   "target": "mitigated" }, 
 {   "stix": "located-at",   "typeql": "located-at",   "source": "locating",   "target": "located" }, 
 {   "stix": "indicates",   "typeql": "indicates",   "source": "indicating",   "target": "indicated" }, 
 {   "stix": "based-on",   "typeql": "based-on",   "source": "basing-on",   "target": "basis" }, 
 {   "stix": "communicates-with",   "typeql": "communicates-with",   "source": "communicating",   "target": "communicated" }, 
 {   "stix": "consists-of",   "typeql": "consist",   "source": "consisting",   "target": "consisted" }, 
 {   "stix": "controls",   "typeql": "control",   "source": "controlling",   "target": "controlled" }, 
 {   "stix": "has",   "typeql": "have",   "source": "having",   "target": "had" }, 
 {   "stix": "hosts",   "typeql": "hosts",   "source": "hosting",   "target": "hosted" }, 
 {   "stix": "owns",   "typeql": "ownership",   "source": "owning",   "target": "owned" }, 
 {   "stix": "authored-by",   "typeql": "authored-by",   "source": "authoring",   "target": "authored" }, 
 {   "stix": "beacons-to",   "typeql": "beacon",   "source": "beaconing-to",   "target": "beaconed-to" }, 
 {   "stix": "exfiltrate-to",   "typeql": "exfiltrate",   "source": "exfiltrating-to",   "target": "exfiltrated-to" }, 
 {   "stix": "downloads",   "typeql": "download",   "source": "downloading",   "target": "downloaded" }, 
 {   "stix": "drops",   "typeql": "drop",   "source": "dropping",   "target": "dropped" }, 
 {   "stix": "exploits",   "typeql": "exploit",   "source": "exploiting",   "target": "exploited" }, 
 {   "stix": "variant-of",   "typeql": "variant",   "source": "variant-source",   "target": "variant-target" }, 
 {   "stix": "characterizes",   "typeql": "characterise",   "source": "characterising",   "target": "characterised" }, 
 {   "stix": "analysis-of",   "typeql": "av-analysis",   "source": "analysing",   "target": "analysed" }, 
 {   "stix": "static-analysis-of",   "typeql": "static-analysis",   "source": "analysing",   "target": "analysed" }, 
 {   "stix": "dynamic-analysis-of",   "typeql": "dynamic-analysis",   "source": "analysing",   "target": "analysed" }, 
 {   "stix": "impersonates",   "typeql": "impersonate",   "source": "impersonating",   "target": "impersonated" }
]

embedded_relations_typeql = [
  {"rel": "object_refs", "owner": "object", "pointed-to": "referred", "typeql": "obj-ref"},
  {"rel": "created_by_ref", "owner": "created", "pointed-to": "creator", "typeql": "created-by"},
  {"rel": "object_marking_refs", "owner": "marked", "pointed-to": "marking", "typeql": "object-marking"},
  {"rel": "sample_refs", "owner": "sample-for", "pointed-to": "sco-sample", "typeql": "malware-sample"},
  {"rel": "sample_ref", "owner": "sample-for", "pointed-to": "sco-sample", "typeql": "malware-analysis-sample"},
  {"rel": "host_vm_ref", "owner": "object", "pointed-to": "env", "typeql": "host-vm-ref"},
  {"rel": "operating_system_ref", "owner": "object", "pointed-to": "env", "typeql": "operating-system"},
  {"rel": "installed_software_refs", "owner": "object", "pointed-to": "env", "typeql": "installed-software"},
  {"rel": "contains_refs", "owner": "container", "pointed-to": "contained", "typeql": "directory-contains"},
  {"rel": "parent_directory_ref", "owner": "contained", "pointed-to": "container", "typeql": "directory-parent"},
  {"rel": "resolves_to_refs", "owner": "resolve", "pointed-to": "resolves-to", "typeql": "resolves"},
  {"rel": "belongs_to_ref", "owner": "belonged", "pointed-to": "belongs-to", "typeql": "belongs"},
  {"rel": "belongs_to_refs", "owner": "belonged", "pointed-to": "belongs-to", "typeql": "belongs-to-autonomous"},
  {"rel": "analysis_sco_refs", "owner": "object", "pointed-to": "env", "typeql": "captured-objects"},
  {"rel": "raw_email_ref", "owner": "email", "pointed-to": "binary", "typeql": "raw-email-references"},
  {"rel": "from_ref", "owner": "email", "pointed-to": "email-address", "typeql": "from-email"},
  {"rel": "sender_ref", "owner": "email", "pointed-to": "email-address", "typeql": "sender-email"},
  {"rel": "to_refs", "owner": "email", "pointed-to": "email-address", "typeql": "to-email"},
  {"rel": "cc_refs", "owner": "email", "pointed-to": "email-address", "typeql": "cc-email"},
  {"rel": "bcc_refs", "owner": "email", "pointed-to": "email-address", "typeql": "bcc-email"},
  {"rel": "body_raw_ref", "owner": "containing-mime", "pointed-to": "non-textual", "typeql": "body-raw-references"},
  {"rel": "content_ref", "owner": "containing-file", "pointed-to": "content", "typeql": "content-file"},
  {"rel": "src_ref", "owner": "traffic", "pointed-to": "source", "typeql": "traffic-src"},
  {"rel": "src_payload_ref", "owner": "traffic", "pointed-to": "source", "typeql": "payload-src"},
  {"rel": "dst_ref", "owner": "traffic", "pointed-to": "destination", "typeql": "traffic-dst"},
  {"rel": "dst_payload_ref", "owner": "traffic", "pointed-to": "payload", "typeql": "payload-dst"},
  {"rel": "encapsulates_refs", "owner": "container", "pointed-to": "contained", "typeql": "encapsulate"},
  {"rel": "encapsulated_by_ref", "owner": "contained", "pointed-to": "container", "typeql": "encapsulated"},
  {"rel": "message_body_data_ref", "owner": "HTPP-message", "pointed-to": "container", "typeql": "HTTP-body-data"},
  {"rel": "opened_connection_refs", "owner": "process", "pointed-to": "opened-connection", "typeql": "open-connections"},
  {"rel": "creator_user_ref", "owner": "created", "pointed-to": "creator", "typeql": "user-created-by"},
  {"rel": "image_ref", "owner": "process", "pointed-to": "executed-image", "typeql": "process-image"},
  {"rel": "parent_ref", "owner": "process", "pointed-to": "parent", "typeql": "process-parent"},
  {"rel": "child_refs", "owner": "process", "pointed-to": "child", "typeql": "process-child"},
  {"rel": "service_dll_refs", "owner": "process", "pointed-to": "loaded-dll", "typeql": "service-dll"}
]



key_value_typeql_list = [
    {
        "name": "additional_header_fields", 
        "typeql": "additional-header", 
        "owner": "email", 
        "pointed_to": "item", 
        "key": "header-key",
        "value": "header-value"
    },{
        "name": "document_info_dict", 
        "typeql": "doc-info", 
        "owner": "pdf", 
        "pointed_to": "info", 
        "key": "doc-key",
        "value": "doc-value"
    },{
        "name": "exif_tags", 
        "typeql": "EXIF-tags", 
        "owner": "image", 
        "pointed_to": "info", 
        "key": "EXIF-key",
        "value": "EXIF-value"
    },{
        "name": "ipfix", 
        "typeql": "IPFIX-store", 
        "owner": "traffic", 
        "pointed_to": "item", 
        "key": "IPFIX-key",
        "value": "IPFIX-value"
    },{
        "name": "request_header", 
        "typeql": "HTTP-header", 
        "owner": "request", 
        "pointed_to": "header", 
        "key": "HTTP-key",
        "value": "HTTP-value"
    },{
        "name": "options", 
        "typeql": "socket-options", 
        "owner": "socket", 
        "pointed_to": "option", 
        "key": "socket-key",
        "value": "socket-value"
    },{
        "name": "environment_variables", 
        "typeql": "environment-variables", 
        "owner": "process", 
        "pointed_to": "env-variable", 
        "key": "environment-key",
        "value": "environment-value"
    },{
        "name": "startup_info", 
        "typeql": "startup-info", 
        "owner": "process", 
        "pointed_to": "option", 
        "key": "startup-key",
        "value": "startup-value"
    }
]



list_of_object_typeql = [
    {
        "name": "body_multipart", 
        "typeql": "body-multipart", 
        "typeql_props": email_mime_part_typeql_dict, 
        "owner": "email", 
        "pointed_to": "mime-part", 
        "object": "email-mime-part"
    },{
        "name": "external_references", 
        "typeql": "external-references", 
        "typeql_props": ext_ref_typeql_dict, 
        "owner": "referencing", 
        "pointed_to": "referenced", 
        "object": "external-reference"
    },{
        "name": "kill_chain_phases", 
        "typeql": "kill-chain-usage", 
        "typeql_props": kill_chain_phases_typeql_dict, 
        "owner": "kill-chain-used", 
        "pointed_to": "kill-chain-using", 
        "object": "kill-chain-phase"
    },{
        "name": "alternate_data_streams", 
        "typeql": "alt-data-streams", 
        "typeql_props": alternate_data_stream_ext_typeql_dict, 
        "owner": "ntfs-ext", 
        "pointed_to": "alt-data-stream", 
        "object": "alternate-data-stream"
    },{
        "name": "sections",
        "typeql_props": windows_pe_section_ext_typeql_dict,
        "object": "windows-pe-section",
        "typeql": "sections", 
        "owner": "pebinary",
        "pointed_to": "pe-section"
    },{
        "name": "values",
        "typeql_props": windows_registry_value_typeql_dict,
        "object": "windows-registry-value-type",
        "typeql": "reg-val", 
        "owner": "reg-key",
        "pointed_to": "reg-value"
    }
]
 

    

#---------------------------------------------------
# 2.5) Object to Dict Mapping
#---------------------------------------------------

dispatch_stix = {
    
    "attack-pattern" :  attack_pattern_typeql_dict,
    "campaign" :  campaign_typeql_dict,
    "course-of-action" :  course_of_action_typeql_dict,
    "grouping" :  grouping_typeql_dict,
    "identity": identity_typeql_dict,
    "incident": incident_typeql_dict,
    "indicator": indicator_typeql_dict,
    "infrastructure": infrastructure_typeql_dict,
    "intrusion-set": intrusion_set_typeql_dict,
    "location": location_typeql_dict,
    "malware": malware_typeql_dict,
    "malware-analysis": malware_analysis_typeql_dict,
    "note" :  note_type_dict,
    "observed-data" :  observed_data_typeql_dict,
    "opinion" :  opinion_typeql_dict,
    "report" :  report_typeql_dict,
    "threat-actor": threat_actor_typeql_dict,
    "tool": tool_typeql_dict,
    "vulnerability": vulnerability_typeql_dict,
    "relationship": relationship_typeql_dict,
    "sighting": sighting_typeql_dict,
    "artifact": artifact_typeql_dict,
    "autonomous-system": autonomous_system_typeql_dict,
    "directory": directory_typeql_dict,
    "domain-name": domain_name_typeql_dict,
    "email-addr": email_addr_typeql_dict,
    "email-message": email_message_typeql_dict,
    "file": file_typeql_dict,
    "ipv4-addr": ipv4_addr_typeql_dict,
    "ipv6-addr": ipv6_addr_typeql_dict,
    "mac-addr": mac_addr_typeql_dict,
    "mutex": mutex_typeql_dict,
    "network-traffic": network_traffic_typeql_dict,
    "process": process_typeql_dict,
    "software": software_typeql_dict,
    "url": url_typeql_dict,
    "user-account": user_account_typeql_dict,
    "windows-registry-key": windows_registry_key_typeql_dict,
    "windows-registry-value-type": windows_registry_value_typeql_dict,
    "x509-certificate": x509_certificate_typeql_dict,
    "external-reference": ext_ref_typeql_dict,
    "email-mime-part": email_mime_part_typeql_dict,
    "archive-ext":  archive_ext_typeql_dict,
    "ntfs-ext":  ntfs_ext_typeql_dict,
    "alternate-data-stream": alternate_data_stream_ext_typeql_dict,
    "pdf-ext": pdf_ext_typeql_dict,
    "raster-image-ext": raster_image_ext_typeql_dict,
    "windows-pebinary-ext": windows_pebinary_ext_typeql_dict,
    "windows-pe-optional-header-type": windows_optional_header_ext_typeql_dict,
    "windows-pe-section": windows_pe_section_ext_typeql_dict,
    "http-request-ext": HTTP_request_ext_typeql_dict,
    "icmp-ext": icmp_ext_typeql_dict,
    "socket-ext": socket_ext_typeql_dict,
    "tcp-ext": tcp_ext_typeql_dict,
    "unix-account-ext": unix_account_ext_typeql_dict,
    "windows-process-ext": windows_process_ext_typeql_dict,
    "windows-service-ext": windows_service_ext_typeql_dict,
    "kill-chain-phase": kill_chain_phases_typeql_dict,
    "x509-v3-extension": x509_v3_ext_typeql_dict
}

sdo_obj = [
    "attack-pattern",
    "campaign" ,
    "course-of-action",
    "grouping",
    "identity",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data" ,
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability"
]

sro_obj = [    
    "relationship",
    "sighting",
    "delivers",
    "targets",
    "uses",
    "attributed-to",
    "compromises",
    "originates-from",
    "investigates",
    "mitigates",
    "located-at",
    "indicates",
    "based-on",
    "communicates-with",
    "consist",
    "control",
    "have",
    "hosts",
    "ownership",
    "authored-by",
    "beacon",
    "exfiltrate",
    "download",
    "drop",
    "exploit",
    "variant",
    "characterise",
    "impersonate",
    "av-analysis",
    "static-analysis",
    "dynamic-analysis",
    "remediation"
]

sco_obj =[   
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "windows-registry-value-type",
    "x509-certificate"
]    
    
meta_obj = [
    "marking-definition",
    "tlp-white",
    "tlp-green",
    "tlp-amber",
    "tlp-red",
    "statement-marking"
]
    

dispatch_attack = {}

extensions_only = [
    "archive-extension",
    "ntfs-extension",
    "pdf-extension",
    "raster-image-extension",
    "windows-pebinary-extension",
    "http-request-extension",
    "icmp-extension",
    "socket-extension",
    "tcp-extension",
    "unix-account-extension",
    "windows-process-extension",
    "windows-service-extension"
]

object_is_list = {
    "external-reference": [],
    "email-mime-part": [],
    "archive-ext":  ["contains_refs"],
    "ntfs-ext":  ["alternate_data_streams"],
    "alternate-data-stream": [],
    "pdf-ext": [],
    "raster-image-ext": [],
    "windows-pebinary-ext": ["sections"],
    "windows-pe-optional-header-type": [],
    "windows-pe-section": [],
    "http-request-ext": [],
    "icmp-ext": [],
    "socket-ext": [],
    "tcp-ext": [],
    "unix-account-ext": ["groups"],
    "windows-process-ext": [],
    "windows-service-ext": ["descriptions", "service_dll_refs"],
    "kill-chain-phase": [],
    "windows-registry-value-type": [],
    "x509-v3-extension": []
}

sdo_is_list = {
    "sdo": ["labels","external_references", "object_marking_refs", "granular_markings"],
    "attack-pattern": ["aliases", "kill_chain_phases"],
    "campaign": ["aliases"],
    "course-of-action": [],
    "grouping": ["object_refs"],
    "identity": ["roles", "sectors"],
    "incident": [],
    "indicator": ["indicator_types", "kill_chain_phases"],
    "infrastructure": ["infrastructure_types", "aliases", "kill_chain_phases"],
    "intrusion-set": ["aliases", "goals", "secondary_motivations" ],
    "location": [],
    "malware": ["malware_types", "kill_chain_phases","aliases", "operating_system_refs", "architecture_execution_envs", "implementation_languages", "capabilities", "sample_refs"],
    "malware-analysis": ["installed_software_refs", "modules", "analysis_sco_refs"],
    "note": ["authors", "object_refs"],
    "observed-data": ["object_refs"],
    "opinion": ["authors", "object_refs"],
    "report": ["report_types", "object_refs"],
    "threat-actor": ["threat_actor_types", "aliases", "roles", "goals","resource-level", "secondary_motivations", "personal_motivations"],
    "tool": ["tool_types", "kill_chain_phases", "aliases"],
    "vulnerability": []
}

sro_is_list = {
    "sro": ["labels","external_references", "object_marking_refs", "granular_markings"],
    "sighting": [ "observed_data_refs", "where_sighted_refs"]
}

sco_is_list = {
    "sco": ["labels","external_references", "object_marking_refs", "granular_markings"],
    "artifact": [],
    "autonomous-system": [],
    "directory": ["contains_refs"],
    "domain-name": ["resolves_to_refs"],
    "email-addr": [],
    "email-message": ["to_refs", "cc_refs", "bcc_refs", "received_lines", "body_multipart"],
    "email-mime-part": [],
    "file": ["contains_refs"],    
    "archive-ext":  ["contains_refs"],
    "ntfs-ext":  ["alternate_data_streams"],
    "alternate-data-stream-type": [],
    "pdf-ext": [],
    "raster-image-ext": [],
    "windows-pebinary-ext": ["sections"],
    "windows-pe-optional-header-type": [],
    "windows-pe-section-type": [],
    "ipv4-addr": ["resolves_to_refs", "belongs_to_refs"],
    "ipv6-addr": ["resolves_to_refs", "belongs_to_refs"],
    "mac-addr": [],
    "mutex": [],
    "network-traffic": [ "protocols", "encapsulates_refs"],
    "http-request-ext": [],
    "icmp-ext": [],
    "socket-ext": [],
    "tcp-ext": [],
    "process": ["opened_connection_refs", "child_refs"],
    "windows-process-ext": [],
    "windows-service-ext": ["descriptions", "service_dll_refs"],
    "software": ["languages"],
    "url": [],
    "user-account": [],
    "unix-account-ext": ["groups"],
    "windows-registry-key": ["values"],
    "windows-registry-value-type": [],
    "x509-certificate": [],
    "x509-v3-extensions-type": []
}

###################################################################################################
###################################################################################################
#
#    TypeQL to Stix Mapping
#
###################################################################################################

embedded_relations = [x["typeql"] for x in embedded_relations_typeql]
standard_relations = [x["typeql"] for x in stix_rel_roles]
list_of_objects = [x["typeql"] for x in list_of_object_typeql]
key_value_relations = [x["typeql"] for x in key_value_typeql_list]
extension_relations = [x["relation"] for x in ext_typeql_dict_list]

#--------------------------------------------------------------------------------------------------------
#  Overview:
#     1. Convert TypeQL Ans to Res, using the transaction
#     2. Convert Res to Stix, creating first the dict, then parsing the dict to Stix object
#--------------------------------------------------------------------------------------------------------

@logger.catch
def convert_ans_to_stix(answer_iterator, r_tx, import_type):
    res = convert_ans_to_res(answer_iterator, r_tx, import_type)    
    with open("export_test.json", "w") as outfile:  
        json.dump(res, outfile) 
    stix_dict = convert_res_to_stix(res, import_type)
    #stix_object = parse(stix_dict)
    return stix_dict

#--------------------------------------------------------------------------------------------------------
#  2. Convert Res to Stix
#--------------------------------------------------------------------------------------------------------
    
def convert_res_to_stix(res, import_type):
    for object in res:
        obj_type = object["T_name"]
        tql_type = object["type"]
        if obj_type in sdo_obj:
            stix_dict = make_sdo(object, import_type)
        elif obj_type in sco_obj:
            stix_dict = make_sco(object, import_type)
        elif obj_type in sro_obj:
            stix_dict = make_sro(object, import_type)
        elif obj_type in meta_obj:
            stix_dict = make_meta(object, import_type)
        else:
            logger.error(f'Unknown object type: {object}')     
            stix_dict={}   
        
    return stix_dict
    
def make_sdo(res, import_type):    
    stix_dict = {}
    obj_type = res["T_name"]
    # 1.B) get the specific typeql names for an object into a dictionary
    # - stix import
    if import_type == 'Stix21':
        if obj_type in dispatch_stix:
            obj_tql = dispatch_stix[obj_type]
        else:
            logger.error(f'obj_type type {obj_type} not supported')
            return ''
    # - mitre attack import
    elif import_type == 'mitre':
        if obj_type[0:6] == "x-mitre":
            if obj_type in dispatch_mitre:
                # dispatch specific mitre properties plus generic sdo properties
                obj_tql = dispatch_mitre[obj_type]
            else:
                logger.error(f'obj_type type {obj_type} not in dispatch mitre')
                return ''
        else:
            if obj_type in dispatch_stix:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = dispatch_stix[obj_type]
                obj_tql2 = dispatch_mitre[obj_type]
                obj_tql.update(obj_tql2)
            else:
                logger.error(f'obj_type type {obj_type} not in dispatch_stix or dispatch mitre')
                return ''              
        
    else:
        logger.error(f'import type {import_type} not supported')
        return ''	
    
    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    obj_tql.update(stix_models['sdo_typeql_dict'])
    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    # 2.B) get the is_list list, the list of properties that are lists for that object
    is_list = sdo_is_list["sdo"] + sdo_is_list[obj_type]
    # 3.A) add the properties onto the the object
    stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
    # 3.B) add the relations onto the object
    stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, obj_type)
        
    return stix_dict

def make_sro(res, import_type):    
    stix_dict = {}
    obj_type = res["T_name"]
    if obj_type == "sighting":
        obj_tql = dispatch_stix["sighting"]
        
    elif obj_type in standard_relations:
        obj_tql = dispatch_stix["relationship"]
        
    else:
      logger.error(f'relationship type {obj_type} not supported')
      return ''
    
    # - add on the generic sro properties
    obj_tql.update(sro_base_typeql_dict)
    
    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    edges = res["edges"]	
    # 2.) setup the match statements first, depending on whether the object is a sighting or a relationship
    # A. If it is a Relationship then find the source and target roles for the relation, and match them in
    if obj_type in standard_relations:
        for stix_rel in stix_rel_roles:
            if stix_rel["typeql"] == obj_type:
                source_role = stix_rel["source"]
                target_role = stix_rel["target"]
                break
        
        is_list = sro_is_list["sro"]
        for edge in edges:
            players = edge["player"]
            if edge["role"] == source_role:
                for p in players:
                    stix_dict["source_ref"] = p["stix_id"]
                    break
                    
            elif edge["role"] == target_role:
                for p in players:
                    stix_dict["target_ref"] = p["stix_id"]
                    break
            else:
                logger.error(f'edge role {edge["role"]} not supported')
                return ''
                
    # B. If it is a Sighting then match the object to the sighting
    elif obj_type == 'sighting':
        is_list = sro_is_list["sro"] + sro_is_list["sighting"]
        for edge in edges:
            players = edge["player"]
            if edge["role"] == "sighting-of":
                for p in players:
                    stix_dict["sighting_of_ref"] = p["stix_id"]
                    
            elif edge["role"] == "where-sighted":
                for p in players:
                    if "where_sighted_refs" in stix_dict:
                        stix_dict["where_sighted_refs"].append(p["stix_id"])	
                    else:
                        stix_dict["where_sighted_refs"] = []
                        stix_dict["where_sighted_refs"].append(p["stix_id"])
            elif edge["role"] == "observed":
                for p in players:
                    if "observed_data_refs" in stix_dict:
                        stix_dict["observed_data_refs"].append(p["stix_id"])	
                    else:
                        stix_dict["observed_data_refs"] = []
                        stix_dict["observed_data_refs"].append(p["stix_id"])
            else:
                logger.error(f'edge role {edge["role"]} not supported')
                return ''
        
    else:
      logger.error(f'relationship type {obj_type} not supported')
      return ''
    
    # 3.A) add the properties onto the the object
    stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
    # 3.B) add the relations onto the object
    stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, obj_type)
    return stix_dict
    
    
def make_sco(res, import_type):   
    # - work out the type of object
    stix_dict = {}
    obj_type = res["T_name"]
    # - get the object-specific typeql names, sighting or relationship
    obj_tql = dispatch_stix[obj_type]
    # - add on the generic sro properties
    obj_tql.update(sco_base_typeql_dict)
    
    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    
    is_list = sco_is_list["sco"] + sco_is_list[obj_type]
    # 3.A) add the properties onto the the object
    stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
    # 3.B) add the relations onto the object
    stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, obj_type)
    return stix_dict
    
colours_dict = {
    "tlp-amber": {"type": "marking-definition", "spec_version": "2.1", 
            "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": "TLP:AMBER", "definition": { "tlp": "amber" }},
    "tlp-green": {"type": "marking-definition", "spec_version": "2.1", 
            "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": "TLP:GREEN", "definition": { "tlp": "green" }},
    "tlp-white": {"type": "marking-definition", "spec_version": "2.1", 
            "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": "TLP:WHITE", "definition": { "tlp": "white" }},
    "tlp-red": {"type": "marking-definition", "spec_version": "2.1", 
            "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": "TLP:RED", "definition": { "tlp": "red" }}
}
    
def make_meta(res, import_type):    
    stix_dict = {}
    obj_type = res["T_name"]
    props = res["has"]
    if obj_type == "tlp-white" or obj_type == "tlp-green" or obj_type == "tlp-amber" or obj_type == "tlp-red":
        return colours_dict[obj_type]
    elif obj_type == "statement-marking":
        stix_dict["definition_type"] = "statement"
        stix_dict["type"] = "marking-definition"
        for prop in props:
            if prop["typeql"] == "stix-id":
                stix_dict["id"] = prop["value"]
            elif prop["typeql"] == "spec-version":
                stix_dict["spec_version"] = prop["value"]
            elif prop["typeql"] == "created":
                stix_dict["created"] = prop["value"]
            elif prop["typeql"] == "statement":
                temp_dict = {}
                temp_dict["statement"] = prop["value"]
                stix_dict["definition"] = temp_dict	
    
    else:
        logger.error(f' make meta type not implemented {obj_type}')
    
    return stix_dict
    
def make_properties(props, obj_tql, stix_dict, is_list):
    for prop in props:
        prop_tql_name = prop["typeql"]
        prop_value = prop["value"]
        for stix_name, stix_value in obj_tql.items():
            if prop_tql_name == stix_value:
                # if property is a list, then
                if stix_name in is_list:
                    if stix_name not in stix_dict:
                        stix_dict[stix_name] = []
                        stix_dict[stix_name].append(prop_value)
                        break
                    else:
                        stix_dict[stix_name].append(prop_value)
                        break
                # else property is a value, not a list    
                else:        
                    stix_dict[stix_name] = prop_value
        
    return stix_dict
    
def make_relations(relns, obj_tql, stix_dict, is_list, obj_name=None):
    for reln in relns:
        reln_name = reln["T_name"]
        if reln_name in embedded_relations:
            stix_dict = make_embedded_relations(reln, reln_name, stix_dict, is_list, obj_name)
            
        elif reln_name in standard_relations or reln_name == "sighting":
            stix_dict = make_standard_relations(reln, reln_name, stix_dict, is_list, obj_name)
            
        elif reln_name in key_value_relations:
            stix_dict = make_key_value_relations(reln, reln_name, stix_dict, is_list, obj_name)
            
        elif reln_name in extensions_only:
            stix_dict = make_extension_relations(reln, reln_name, stix_dict, is_list, obj_name)
            
        elif reln_name in list_of_objects:
            stix_dict = make_list_of_objects(reln, reln_name, stix_dict, is_list, obj_name)
            
        elif reln_name in extension_relations:
            stix_dict = make_object(reln, reln_name, stix_dict, is_list, obj_name)
            
        elif reln_name == "granular-marking":
            stix_dict = make_granular_marking(reln, reln_name, stix_dict, is_list, obj_tql, obj_name)
            
        elif reln_name == "hashes":
            stix_dict = make_hashes(reln, reln_name, stix_dict)    
            
        else:
            logger.error(f'Error, relation name is {reln_name}')
            break
                
    return stix_dict
    
def make_embedded_relations(reln, reln_name, stix_dict, is_list, obj_name):
    stix_object_type = obj_name
    for embedded_r in embedded_relations_typeql:
        if reln_name == embedded_r["typeql"]:
            role_pointed = embedded_r["pointed-to"]            
            stix_name = embedded_r["rel"]
            role_owner = embedded_r["owner"]
            
    roles = reln["roles"]
    for role in roles:
        if role["role"] == role_pointed:
            pointed = role
        elif role["role"] == role_owner:
            owner = role
        else:
            logger.error(f'unsupported role in embedded relation {role["role"]}')
    
    # 1. Is Owner correct, basically my super object?
    # - should be only one object in the owner role list, and its type is the same as my super object type
    own_players = owner["player"]
    own_player = own_players[0]
    if own_player['tql'] == stix_object_type:
        # 2. If 1 is yes, then we want to find the emebedded relation, else not    
        pointed_players = pointed["player"]
        for p in pointed_players:
            prop_value = p['stix_id']
            # if property is a list, then
            if stix_name in is_list:
                if stix_name not in stix_dict:
                    stix_dict[stix_name] = []
                    stix_dict[stix_name].append(prop_value)
                    
                else:
                    stix_dict[stix_name].append(prop_value)
                    
            # else property is a value, not a list    
            else:        
                stix_dict[stix_name] = prop_value
    else:
        return stix_dict
                                
            
    return stix_dict
    
def make_standard_relations(reln, reln_name, stix_dict, is_list, obj_name=None):
    logger.warning(" make standard relations visited, but not implemented")
    return stix_dict
    

    
    
def make_key_value_relations(reln, reln_name, stix_dict, is_list, obj_type=None):
    for kv_obj in key_value_typeql_list:
        if reln_name == kv_obj["typeql"]:
            role_pointed = kv_obj["pointed_to"]
            reln_owner = kv_obj["owner"]
            key_name = kv_obj["key"]
            val_name = kv_obj["value"]
            stix_field_name = kv_obj["name"]
            break            
    
    roles = reln["roles"]
    dict_of_kv = {}
    for role in roles:
        if role["role"] == role_pointed:
            players = role["player"]            
            for p in players:
                key_value = p["value"]
                props = p['props']
                prop_list = []
                if len(props) > 1:
                    for prop in props:
                        val_value = prop["value"]
                        prop_list.append(val_value)
                    
                    dict_of_kv[key_value] = prop_list
                
                else:
                    val_value = props[0]["value"]
                    dict_of_kv[key_value] = val_value
    
    stix_dict[stix_field_name] = dict_of_kv
    return stix_dict



def make_extension_relations(reln, reln_name, stix_dict, is_list, obj_type=None):
    local_dict = {}
    local_dict = make_object(reln, reln_name, local_dict, is_list, obj_type)
    stix_dict["extensions"] = local_dict
    return stix_dict
    
def make_object(reln, reln_name, stix_dict, is_list, obj_type=None):
    for ext_obj in ext_typeql_dict_list:
        if reln_name == ext_obj["relation"]:
            role_pointed = ext_obj["pointed-to"]
            role_owner = ext_obj["owner"]
            ext_object = ext_obj["object"]
            obj_props_tql = ext_obj["dict"]
            stix_ext_name = ext_obj["stix"]
            obj_is_list = object_is_list[ext_object]
            break         
    
    roles = reln["roles"]
    ext_data_object = {}
    for role in roles:
        if role["role"] == role_pointed:
            players = role["player"]            
            for p in players:
                player = {}
                # get properties for the sub object
                props = p['has']
                for prop in props:
                    prop_name = prop["typeql"]
                    prop_stix_name = prop_value = None
                    for stix, tql in obj_props_tql.items():
                        if prop_name == tql:
                            prop_stix_name = stix
                            prop_value = prop["value"]
                            break
                    # if property is a list, then
                    if prop_stix_name in obj_is_list:
                        if prop_stix_name not in player:
                            player[prop_stix_name] = []
                            player[prop_stix_name].append(prop_value)
                            
                        else:
                            player[prop_stix_name].append(prop_value)
                            
                    # else property is a value, not a list    
                    else:        
                        player[prop_stix_name] = prop_value
                # now look to see if there are relations
                obj_relns = [k for k,v in obj_props_tql.items() if v == ""]
                sub_relns = p['relns']
                obj_tql = dispatch_stix[ext_object]
                new_dict = {}
                new_dict = make_relations(sub_relns, obj_tql, new_dict, is_list, ext_object)
                for k,v in new_dict.items():
                    player[k] = v
                    
    stix_dict[stix_ext_name] = player
    return stix_dict


    
def make_list_of_objects(reln, reln_name, stix_dict, is_list, obj_type=None):
    for l_obj in list_of_object_typeql:
        if reln_name == l_obj["typeql"]:
            role_pointed = l_obj["pointed_to"]
            reln_object = l_obj["object"]
            obj_props_tql = l_obj["typeql_props"]
            stix_field_name = l_obj["name"]
            obj_is_list = object_is_list[reln_object]
            break            
    
    roles = reln["roles"]
    list_of_objects = []
    for role in roles:
        if role["role"] == role_pointed:
            players = role["player"]            
            for p in players:
                player = {}
                # get properties for the sub object
                props = p['has']
                for prop in props:
                    prop_name = prop["typeql"]
                    prop_stix_name = prop_value = None
                    for stix, tql in obj_props_tql.items():
                        if prop_name == tql:
                            prop_stix_name = stix
                            prop_value = prop["value"]
                            break
                    # if property is a list, then
                    if prop_stix_name in obj_is_list:
                        if prop_stix_name not in player:
                            player[prop_stix_name] = []
                            player[prop_stix_name].append(prop_value)
                            
                        else:
                            player[prop_stix_name].append(prop_value)
                            
                    # else property is a value, not a list    
                    else:        
                        player[prop_stix_name] = prop_value
                # now look to see if there are relations
                obj_relns = [k for k,v in obj_props_tql.items() if v == ""]
                sub_relns = p['relns']
                for sub_reln in sub_relns:
                    # if the relation is embedded
                    if sub_reln["T_name"] in embedded_relations:
                        for inst in embedded_relations_typeql:
                            if inst["typeql"] == sub_reln["T_name"]:
                                obj_reln_name = inst["typeql"]
                                obj_owner = inst["owner"]
                                obj_pointed = inst["pointed-to"]
                                obj_stix_name = inst["rel"]
                                break
                            
                        local_roles = sub_reln["roles"]
                        for l_r in local_roles:
                            # if the owner role  is considered
                            if l_r["role"] == obj_owner:
                                local_players = l_r["player"]
                                # and the existing object used in the list of objects
                                if local_players[0]["tql"] == reln_object:
                                    for l_r2 in local_roles:
                                        if l_r2["role"] == obj_pointed:
                                            players2 = l_r2["player"]
                                            for p2 in players2:
                                                # then we write the result as an embedded relation
                                                answer = p2['stix_id']
                                                if obj_stix_name in obj_is_list:
                                                    if obj_stix_name not in player:
                                                        player[obj_stix_name] = []
                                                        player[obj_stix_name].append(answer)
                                                        
                                                    else:
                                                        player[obj_stix_name].append(answer)
                                                
                                                else:
                                                    player[obj_stix_name] = answer
                                
                
                    #else:
                        #logger.debug(f'unsupported relation for list of objects {sub_reln}')
                        #print(f'embedded --> {embedded_relations_typeql}')
                        
                list_of_objects.append(player)
    
    stix_dict[stix_field_name] = list_of_objects
    return stix_dict


  
    
def make_granular_marking(reln, reln_name, stix_dict, is_list, obj_tql, obj_type=None):
    stix_label = "granular_markings"
    local_marking = {}
    roles = reln["roles"]
    lang_marking = stix_marking = None
    for role in roles:
        if role["role"] == "marking":
            local_p = role["player"][0]
            local_id = local_p["stix_id"]
            local_type = local_id.split('--')[0]
            if local_type == "marking-definition":
                stix_marking = local_id
            else:
                lang_marking = local_id
            
        elif role["role"] == "marked":
            local_p = role["player"]
            selectors = []
            for p in local_p:
                tql_name = p["tql"]
                stix_name = ''
                for key, value in obj_tql.items():
                    if value == tql_name:
                        stix_name = key
                        break
                
                # if property being marked is a list, then
                if stix_name in is_list:
                    # find the item in the property list with the same value, as my typeql value
                    tql_value = p["value"]
                    list_to_check = stix_dict[stix_name]
                    for i, item in enumerate(list_to_check):
                        if item == tql_value:
                            stix_name = stix_name + '.[' + str(i) + ']'
                            selectors.append(stix_name)                    
                    
                # else property is a value, not a list    
                else:        
                    selectors.append(stix_name)
                                
    if stix_marking is not None:
        local_marking["marking_ref"] = stix_marking
        local_marking["selectors"] = selectors
    else:
        local_marking["lang"] = lang_marking
        local_marking["selectors"] = selectors
        
    if "granular_markings" in stix_dict:
        stix_dict["granular_markings"].append(local_marking)
    else:
        stix_dict["granular_markings"] = []
        stix_dict["granular_markings"].append(local_marking)
            
    return stix_dict
    
def make_hashes(reln, reln_name, stix_dict):
    stix_label = "hashes"
    hashes = {}
    roles = reln["roles"]
    for r in roles:
        if r["role"] == "owner":
            own_players = r["player"]
        elif r['role'] == "pointed-to":
            own_players = r["player"]
            for p in own_players:
                hash_type = p["tql"]
                hash_value = p["hash_value"]
                hashes[hash_type] = hash_value
            
        else:
            logger.error(f" make hashes relation not implemented {r['role']}")
    
    stix_dict[stix_label] = hashes        
    return stix_dict

    

    

#--------------------------------------------------------------------------------------------------------
#  1. Convert TypeQl Ans to Res
#--------------------------------------------------------------------------------------------------------


def convert_ans_to_res(answer_iterator, r_tx, import_type):
    res = []
    for answer in answer_iterator:
        dict_answer = answer.map()
        for key, thing in dict_answer.items():
            # pull entity data
            if thing.is_entity():
                #1. describe entity
                ent = {}
                ent['type'] = 'entity'
                ent['symbol'] = key
                ent['T_id'] = thing.get_iid()
                ent['T_name'] = thing.get_type().get_label().name()
                props_obj = thing.as_remote(r_tx).get_has()
                props = []
                #2 get and dsecribe properties
                for a in props_obj:
                    prop = {}
                    prop["typeql"] = a.get_type().get_label().name()
                    if a.is_datetime():
                        dt_obj = a.get_value()
                        prop["value"] = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        prop['datetime'] = True
                    else:
                        prop["value"] = a.get_value()
                        prop['datetime'] = False
                    
                    props.append(prop)

                ent['has'] = props
                #3. get and describe relations
                reln_types = thing.as_remote(r_tx).get_relations()
                relns = []
                for r in reln_types:
                    reln = {}
                    r_name = r.get_type().get_label().name()
                    reln = get_relation_details(r, r_tx)                    
                    relns.append(reln)
                    # if r_name  in standard_relations or r_name == "sighting":
                    #     print(f'ignore standard relationships of type -> {r_name}')
                    #     continue
                    # else:
                    #     reln = get_relation_details(r, r_tx)                    
                    #     relns.append(reln)
                    
                ent['relns'] = relns
                res.append(ent)
                #logger.debug(f'ent -> {ent}')
                
                                
            # pull relation data
            elif thing.is_relation():
                #1. setup basis
                rel = {}
                rel['type'] = 'relation'
                rel['symbol'] = key
                rel['T_id'] = thing.get_iid()
                rel['T_name'] = thing.get_type().get_label().name()
                att_obj = thing.as_remote(r_tx).get_has()
                props = []
                #2 get and dsecribe properties
                for a in att_obj:
                    prop = {}
                    prop["typeql"] = a.get_type().get_label().name()
                    if a.is_datetime():
                        dt_obj = a.get_value()
                        prop["value"] = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        prop['datetime'] = True
                    else:
                        prop["value"] = a.get_value()
                        prop['datetime'] = False
                    
                    props.append(prop)

                rel['has'] = props
                #3. get and describe relations
                reln_types = thing.as_remote(r_tx).get_relations()
                relns = []
                for r in reln_types:
                    reln = {}
                    reln = get_relation_details(r, r_tx)                    
                    relns.append(reln)

                rel['relns'] = relns
                #4. get and describe the edges
                edges = []
                edge_types = thing.as_remote(r_tx).get_players_by_role_type()
                stix_id = r_tx.concepts().get_attribute_type("stix-id")
                for role, things in edge_types.items():
                    edge = {}
                    edge["role"] = role.get_label().name()
                    edge['player'] = []                            
                    for thing in things:                        
                        if thing.is_entity():
                            play={}
                            play["type"] = "entity"
                            play["tql"] = thing.get_type().get_label().name()
                            attr_stix_id = thing.as_remote(r_tx).get_has(attribute_type=stix_id)
                            for attr in attr_stix_id:
                                play["stix_id"] = attr.get_value()
                            edge['player'].append(play)
                    
                    edges.append(edge)
                    
                rel['edges'] = edges
                res.append(rel)
                                             

            # else log out error condition
            else:
                logger.debug(f'Error key is {key}, thing is {thing}')
        
    return res


    


def get_relation_details(r, r_tx):
    reln = {}                    
    reln_name = r.get_type().get_label().name()
    reln['T_name'] = reln_name
    reln['T_id'] = r.get_iid()
    if reln_name in embedded_relations:
        reln['roles'] = get_embedded_relations(r, r_tx)        
        
    elif reln_name in standard_relations or reln_name =="sighting":
        reln['roles'] = get_standard_relations(r, r_tx)
        
    elif reln_name in key_value_relations:
        reln['roles'] = get_key_value_relations(r, r_tx)        
        
    elif reln_name in extension_relations:
        reln['roles'] = get_extension_relations(r, r_tx)        
        
    elif reln_name in list_of_objects:
        reln['roles'] = get_list_of_objects(r, r_tx)
        
    elif reln_name == "granular-marking":
        reln['roles'] = get_granular_marking(r, r_tx)
        
    elif reln_name == "hashes":
        reln['roles'] = get_hashes(r, r_tx)    
        
    else:
        logger.error(f'Error, relation name is {reln_name}')
     
    return reln
                        
 

def get_granular_marking(r, r_tx):
    stix_id = r_tx.concepts().get_attribute_type("stix-id")
    reln_map = r.as_remote(r_tx).get_players_by_role_type()
    roles = []
    for role, player in reln_map.items():
        role_i={}
        role_i['role'] = role.get_label().name()
        role_i['player'] = []
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name()
                attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                for attr in attr_stix_id:
                    play["stix_id"] = attr.get_value()
                role_i['player'].append(play)
            elif p.is_attribute():
                play["type"] = "attribute"
                play["tql"] = p.get_type().get_label().name()
                play["value"] = p.get_value()
                role_i['player'].append(play)
                
            else:
                print(f'player is not entity type {p}')
        
        roles.append(role_i)
    return roles

def get_hashes(r, r_tx):
    roles = []
    stix_id = r_tx.concepts().get_attribute_type("stix-id")
    hash_value = r_tx.concepts().get_attribute_type("hash-value")
    reln_map = r.as_remote(r_tx).get_players_by_role_type()
    
    for role, player in reln_map.items():
        role_i={}
        role_name = role.get_label().name()
        role_i['role'] = role_name
        role_i['player'] = []
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name()
                if role_name == "owner":
                    attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                    for attr in attr_stix_id:
                        play["stix_id"] = attr.get_value()
                else:
                    attr_hash_value = p.as_remote(r_tx).get_has(attribute_type=hash_value)
                    for attr in attr_hash_value:
                        play["hash_value"] = attr.get_value()    
                
                role_i['player'].append(play)            
                
            else:
                print(f'player is not entity type {p}')
        
        roles.append(role_i)
    return roles




def get_key_value_relations(r, r_tx):
    stix_id = r_tx.concepts().get_attribute_type("stix-id")
    reln_map = r.as_remote(r_tx).get_players_by_role_type()
    roles = []
    for role, player in reln_map.items():
        role_i={}
        role_i['role'] = role.get_label().name()
        role_i['player'] = []
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name()
                attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                for attr in attr_stix_id:
                    play["stix_id"] = attr.get_value()
                role_i['player'].append(play)
            elif p.is_attribute():
                play["type"] = "attribute"
                play["tql"] = p.get_type().get_label().name()
                play["value"] = p.get_value()
                att_obj = p.as_remote(r_tx).get_has()
                props = []
                #2 get and dsecribe properties
                for a in att_obj:
                    prop = {}
                    prop["typeql"] = a.get_type().get_label().name()
                    if a.is_datetime():
                        dt_obj = a.get_value()
                        prop["value"] = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        prop['datetime'] = True
                    else:
                        prop["value"] = a.get_value()
                        prop['datetime'] = False
                    
                    props.append(prop)
                    
                play['props'] = props
                role_i['player'].append(play)
                
            else:
                print(f'player is not entity type {p}')
        
        roles.append(role_i)
    return roles

def get_list_of_objects(r, r_tx):    
    reln_name = r.get_type().get_label().name()
    for lot in list_of_object_typeql:
        if reln_name == lot["typeql"]:
            reln_pointed_to = lot["pointed_to"]
            reln_object = lot["object"]
            reln_object_props = lot["typeql_props"]
            reln_stix = lot["name"]
    
    stix_id = r_tx.concepts().get_attribute_type("stix-id")
    reln_map = r.as_remote(r_tx).get_players_by_role_type()
    roles = []
    for role, player in reln_map.items():
        role_i={}
        role_i['role'] = role.get_label().name()
        role_i['player'] = []
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name()
                props_obj = p.as_remote(r_tx).get_has()
                props = []
                #2 get and dsecribe properties
                for a in props_obj:
                    prop = {}
                    prop["typeql"] = a.get_type().get_label().name()
                    if a.is_datetime():
                        dt_obj = a.get_value()
                        prop["value"] = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        prop['datetime'] = True
                    else:
                        prop["value"] = a.get_value()
                        prop['datetime'] = False
                    
                    props.append(prop)

                play['has'] = props
                #3. get and describe relations
                reln_types = p.as_remote(r_tx).get_relations()
                relns = []
                for rel in reln_types:
                    reln = {}                    
                    reln_name = rel.get_type().get_label().name()
                    
                    reln['T_name'] = reln_name
                    reln['T_id'] = rel.get_iid()
                    reln_map = rel.as_remote(r_tx).get_players_by_role_type()
                    roles2 = []
                    for role, player in reln_map.items():
                        role_j={}
                        role_j['role'] = role.get_label().name()
                        role_j['player'] = []
                        for p in player:
                            plays = {}
                            if p.is_entity():
                                plays["type"] = "entity"
                                plays["tql"] = p.get_type().get_label().name()
                                attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                                for attr in attr_stix_id:
                                    plays["stix_id"] = attr.get_value()
                                role_j['player'].append(plays)
                            elif p.is_relation():
                                plays["type"] = "attribute"
                                plays["tql"] = p.get_type().get_label().name()
                                attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                                for attr in attr_stix_id:
                                    plays["stix_id"] = attr.get_value()
                                #play["value"] = p.get_value()
                                role_j['player'].append(plays)
                                
                            else:
                                print(f'player is not entity type {p}')
                        
                        roles2.append(role_j)
                    
                    reln['roles'] = roles2
                    relns.append(reln)

                play['relns'] = relns
                role_i['player'].append(play)
            
                
            else:
                print(f'player is not entity type {p}')
        
        roles.append(role_i)
    return roles

 

def get_embedded_relations(r, r_tx):
    stix_id = r_tx.concepts().get_attribute_type("stix-id")
    reln_map = r.as_remote(r_tx).get_players_by_role_type()
    roles = []
    for role, player in reln_map.items():
        role_i={}
        role_i['role'] = role.get_label().name()
        role_i['player'] = []
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                play["tql"] = p.get_type().get_label().name()
                attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                for attr in attr_stix_id:
                    play["stix_id"] = attr.get_value()
                role_i['player'].append(play)
            elif p.is_relation():
                play["type"] = "attribute"
                play["tql"] = p.get_type().get_label().name()
                attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                for attr in attr_stix_id:
                    play["stix_id"] = attr.get_value()
                #play["value"] = p.get_value()
                role_i['player'].append(play)
                
            else:
                print(f'player is not entity type {p}')
        
        roles.append(role_i)
    return roles


def get_extension_relations(r, r_tx):
    reln_name = r.get_type().get_label().name()
    for ext in ext_typeql_dict_list:
        if ext['relation'] == reln_name:
            reln_object = ext['object']
    
    stix_id = r_tx.concepts().get_attribute_type("stix-id")
    reln_map = r.as_remote(r_tx).get_players_by_role_type()
    roles = []
    for role, player in reln_map.items():
        role_i={}
        role_i['role'] = role.get_label().name()
        role_i['player'] = []
        for p in player:
            play = {}
            if p.is_entity():
                play["type"] = "entity"
                p_name = p.get_type().get_label().name()
                play["tql"] = p_name
                if p_name == reln_object:
                    props_obj = p.as_remote(r_tx).get_has()
                    props = []
                    #2 get and dsecribe properties
                    for a in props_obj:
                        prop = {}
                        prop["typeql"] = a.get_type().get_label().name()
                        if a.is_datetime():
                            dt_obj = a.get_value()
                            prop["value"] = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                            prop['datetime'] = True
                        else:
                            prop["value"] = a.get_value()
                            prop['datetime'] = False
                        
                        props.append(prop)

                    play['has'] = props
                    #3. get and describe relations
                    reln_types = p.as_remote(r_tx).get_relations()
                    relns = []
                    for rel in reln_types:
                        reln = {}                 
                        reln = validate_get_relns(rel, r_tx, reln_object)
                        if reln == {} or reln is None:
                            pass
                        else:
                            relns.append(reln)

                    play['relns'] = relns
                
                else:
                    attr_stix_id = p.as_remote(r_tx).get_has(attribute_type=stix_id)
                    for attr in attr_stix_id:
                        play["stix_id"] = attr.get_value()
                        
                role_i['player'].append(play)
            elif p.is_attribute():
                play["type"] = "attribute"
                play["tql"] = p.get_type().get_label().name()
                play["value"] = p.get_value()
                role_i['player'].append(play)
                
            else:
                print(f'player is not entity type {p}')
        
        roles.append(role_i)
    return roles



def validate_get_relns(rel, r_tx, obj_name):
    reln_name = rel.get_type().get_label().name()                        
    if reln_name in embedded_relations:
        for emb in embedded_relations_typeql:
            if emb['typeql'] == reln_name:
                role_owner = emb['owner']
                role_pointd = emb['pointed-to']
                
        reln_map = rel.as_remote(r_tx).get_players_by_role_type()
        for role, player in reln_map.items():
            role_name = role.get_label().name()
            if role_name == role_owner:
                for p in player:
                    if p.is_entity():
                        play_name = p.get_type().get_label().name()
                        if play_name == obj_name:
                            return get_relation_details(rel, r_tx)        
        
    elif reln_name in key_value_relations:
        for kvt in key_value_typeql_list:
            if kvt['typeql'] == reln_name:
                role_owner = kvt['owner']
                role_pointd = kvt['pointed_to']
                
        reln_map = rel.as_remote(r_tx).get_players_by_role_type()
        for role, player in reln_map.items():
            role_name = role.get_label().name()
            if role_name == role_owner:
                for p in player:
                    if p.is_entity():
                        play_name = p.get_type().get_label().name()
                        if play_name == obj_name:
                            return get_relation_details(rel, r_tx)    
                            
    elif reln_name in extension_relations:
        for kvt in ext_typeql_dict_list:
            if kvt['relation'] == reln_name:
                role_owner = kvt['owner']
                role_pointd = kvt['pointed-to']
                
        reln_map = rel.as_remote(r_tx).get_players_by_role_type()
        for role, player in reln_map.items():
            role_name = role.get_label().name()
            if role_name == role_owner:
                for p in player:
                    if p.is_entity():
                        play_name = p.get_type().get_label().name()
                        if play_name == obj_name:
                            return get_relation_details(rel, r_tx)    
                            
    elif reln_name in list_of_objects:
        for kvt in list_of_object_typeql:
            if kvt['typeql'] == reln_name:
                role_owner = kvt['owner']
                role_pointd = kvt['pointed-to']
                
        reln_map = rel.as_remote(r_tx).get_players_by_role_type()
        for role, player in reln_map.items():
            role_name = role.get_label().name()
            if role_name == role_owner:
                for p in player:
                    if p.is_entity():
                        play_name = p.get_type().get_label().name()
                        if play_name == obj_name:
                            return get_relation_details(rel, r_tx)    
                            
    elif reln_name == "granular-marking":
        return get_relation_details(rel, r_tx) 
                               
                            
    elif reln_name == "hashes":
        return get_relation_details(rel, r_tx)  
                            
    else:
        logger.error(f'Error, relation name is {reln_name}')
        
    
    
    

def get_standard_relations(r, r_tx):
    return []


