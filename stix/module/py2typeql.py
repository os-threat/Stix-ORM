import json
import types
import datetime
from loguru import logger
from stix2 import *
from stix2.v21 import *
from stix2.utils import is_object, is_stix_type, get_type_from_id, is_sdo, is_sco, is_sro
from stix2.parsing import parse
from stix.module.definitions.stix21 import stix_models


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
    obj_tql = stix_models["dispatch_stix"][obj_type]
    # - add on the generic sro properties
    obj_tql.update(stix_models["sco_base_typeql_dict"])
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
        for ext_type_ql in stix_models["ext_typeql_dict_list"]:
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
    for prop_type in stix_models["ext_typeql_dict_list"]:
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
    for config in stix_models["list_of_object_typeql"]:
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
    for config in stix_models["key_value_typeql_list"]:
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
        if key in stix_models["hash_typeql_dict"]:
            insert += ' ' + hash_var + ' isa ' + stix_models["hash_typeql_dict"][key] + ', has hash-value ' + val_tql(prop_dict[key]) + ';\n'        
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



#


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
    for ex in stix_models["embedded_relations_typeql"]:
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
        
###################################################################################################
###################################################################################################
#
#    TypeQL to Stix Mapping
#
###################################################################################################

embedded_relations = [x["typeql"] for x in stix_models["embedded_relations_typeql"]]
standard_relations = [x["typeql"] for x in stix_models["stix_rel_roles"]]
list_of_objects = [x["typeql"] for x in stix_models["list_of_object_typeql"]]
key_value_relations = [x["typeql"] for x in stix_models["key_value_typeql_list"]]
extension_relations = [x["relation"] for x in stix_models["ext_typeql_dict_list"]]

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
        if obj_type in stix_models["sdo_obj"]:
            stix_dict = make_sdo(object, import_type)
        elif obj_type in stix_models["sco_obj"]:
            stix_dict = make_sco(object, import_type)
        elif obj_type in stix_models["sro_obj"]:
            stix_dict = make_sro(object, import_type)
        elif obj_type in stix_models["meta_obj"]:
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
        if obj_type in stix_models["dispatch_stix"]:
            obj_tql = stix_models["dispatch_stix"][obj_type]
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
            if obj_type in stix_models["dispatch_stix"]:
                # dispatch specific stix properties plus mitre properties plus generic sdo properties
                obj_tql = stix_models["dispatch_stix"][obj_type]
                obj_tql2 = dispatch_mitre[obj_type]
                obj_tql.update(obj_tql2)
            else:
                logger.error(f'obj_type type {obj_type} not in stix_models["dispatch_stix"] or dispatch mitre')
                return ''              
        
    else:
        logger.error(f'import type {import_type} not supported')
        return ''	
    
    # 1.C) Add the standard object properties to the specific ones, and split them into properties and relations
    obj_tql.update(stix_models["sdo_typeql_dict"])
    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    # 2.B) get the is_list list, the list of properties that are lists for that object
    is_list = stix_models["sdo_is_list"]["sdo"] + stix_models["sdo_is_list"][obj_type]
    # 3.A) add the properties onto the the object
    stix_dict = make_properties(props, obj_tql, stix_dict, is_list)
    # 3.B) add the relations onto the object
    stix_dict = make_relations(relns, obj_tql, stix_dict, is_list, obj_type)
        
    return stix_dict

def make_sro(res, import_type):    
    stix_dict = {}
    obj_type = res["T_name"]
    if obj_type == "sighting":
        obj_tql = stix_models["dispatch_stix"]["sighting"]
        
    elif obj_type in standard_relations:
        obj_tql = stix_models["dispatch_stix"]["relationship"]
        
    else:
      logger.error(f'relationship type {obj_type} not supported')
      return ''
    
    # - add on the generic sro properties
    obj_tql.update(stix_models["sro_base_typeql_dict"])
    
    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    edges = res["edges"]	
    # 2.) setup the match statements first, depending on whether the object is a sighting or a relationship
    # A. If it is a Relationship then find the source and target roles for the relation, and match them in
    if obj_type in standard_relations:
        for stix_rel in stix_models["stix_rel_roles"]:
            if stix_rel["typeql"] == obj_type:
                source_role = stix_rel["source"]
                target_role = stix_rel["target"]
                break
        
        is_list = stix_models["sro_is_list"]["sro"]
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
        is_list = stix_models["sro_is_list"]["sro"] + stix_models["sro_is_list"]["sighting"]
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
    obj_tql = stix_models["dispatch_stix"][obj_type]
    # - add on the generic sro properties
    obj_tql.update(stix_models["sco_base_typeql_dict"])
    
    # 2.A) get the typeql properties and relations
    props = res["has"]
    relns = res["relns"]
    
    is_list = stix_models["sco_is_list"]["sco"] + stix_models["sco_is_list"][obj_type]
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
            
        elif reln_name in stix_models["extensions_only"]:
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
    for embedded_r in stix_models["embedded_relations_typeql"]:
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
    for kv_obj in stix_models["key_value_typeql_list"]:
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
    for ext_obj in stix_models["ext_typeql_dict_list"]:
        if reln_name == ext_obj["relation"]:
            role_pointed = ext_obj["pointed-to"]
            role_owner = ext_obj["owner"]
            ext_object = ext_obj["object"]
            obj_props_tql = ext_obj["dict"]
            stix_ext_name = ext_obj["stix"]
            obj_is_list = stix_models["object_is_list"][ext_object]
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
                obj_tql = stix_models["dispatch_stix"][ext_object]
                new_dict = {}
                new_dict = make_relations(sub_relns, obj_tql, new_dict, is_list, ext_object)
                for k,v in new_dict.items():
                    player[k] = v
                    
    stix_dict[stix_ext_name] = player
    return stix_dict


    
def make_list_of_objects(reln, reln_name, stix_dict, is_list, obj_type=None):
    for l_obj in stix_models["list_of_object_typeql"]:
        if reln_name == l_obj["typeql"]:
            role_pointed = l_obj["pointed_to"]
            reln_object = l_obj["object"]
            obj_props_tql = l_obj["typeql_props"]
            stix_field_name = l_obj["name"]
            obj_is_list = stix_models["object_is_list"][reln_object]
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
                        for inst in stix_models["embedded_relations_typeql"]:
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
                        #print(f'embedded --> {stix_models["embedded_relations_typeql"]}')
                        
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
    for lot in stix_models["list_of_object_typeql"]:
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
    for ext in stix_models["ext_typeql_dict_list"]:
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
        for emb in stix_models["embedded_relations_typeql"]:
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
        for kvt in stix_models["key_value_typeql_list"]:
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
        for kvt in stix_models["ext_typeql_dict_list"]:
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
        for kvt in stix_models["list_of_object_typeql"]:
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


