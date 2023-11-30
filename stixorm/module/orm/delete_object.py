import re
from typing import List
import copy

from stixorm.module.authorise import authorised_mappings

from stixorm.module.orm.import_objects import sdo_to_data, sro_to_data, sco_to_data
from stixorm.module.orm.import_utilities import split_on_activity_type, val_tql

import logging

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance

logger = logging.getLogger(__name__)

##############################################################
#  1.) Methods to Delete any Stix Objects
############################################################

#---------------------------------------------------
# 1.0) Helper method to direct the right typeql method to an incoming Stix object
#---------------------------------------------------


def delete_stix_object(stix_object,
                       dep_match: str,
                       dep_insert: str,
                       indep_ql: str,
                       core_ql: str,
                       import_type) -> [str, str]:
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    if stix_object.type in auth["types"]["sdo"]:
        total_props, obj_tql, sdo_tql_name, protocol = sdo_to_data(stix_object, import_type)
        var_name: List[str] = get_obj_var(indep_ql)
        del_match, del_tql = delete_object(stix_object, core_ql, total_props, obj_tql, var_name, sdo_tql_name, import_type)
    elif stix_object.type in auth["types"]["sro"]:
        total_props, obj_tql, sro_tql_name, protocol = sro_to_data(stix_object, import_type)
        var_name: List[str] = get_obj_var(dep_insert)
        del_match, del_tql = delete_object(stix_object, core_ql, total_props, obj_tql, var_name, sro_tql_name, import_type)
    elif stix_object.type in auth["types"]["sco"]:
        total_props, obj_tql, sro_tql_name, protocol = sco_to_data(stix_object, import_type)
        var_name: List[str] = get_obj_var(core_ql)
        # Need to change this line to suit scenarios where object name is not type name (e.g. future)
        del_match, del_tql = delete_object(stix_object, core_ql, total_props, obj_tql, var_name, sro_tql_name, import_type)
    elif stix_object.type == 'marking-definition':
        del_match, del_tql = delete_marking(stix_object, dep_match, dep_insert, indep_ql, core_ql, import_type)
    else:
        logger.error(f'object type not supported in delete stix object: {stix_object.type}')
        logger.error(f' import type {dep_match + dep_insert + indep_ql + core_ql}')
        del_match = del_tql = ""

    return del_match, del_tql


def delete_object(stix_object,
                  core_ql: str,
                  total_props,
                  obj_tql,
                  var_name: List[str],
                  tql_name: str,
                  import_type) -> [str, str]:
    # 1.B) get the data model
    properties, relations = split_on_activity_type(total_props, obj_tql)
    # 2.0) MAtch in the object, the id and all attributes not owned by another object
    del_match = 'match \n' + core_ql
    del_match += var_name[0] + ' has $a;\n'
    del_match += 'not { ' + var_name[0] + ' isa thing; $p2 isa thing, has $a; not {'
    del_match += var_name[0] + ' is $p2;}; };\n\n'
    del_tql = 'delete \n'
    # 3.0) Now setup the match and delete statements for the local relations or  sub objects
    for i, reln in enumerate(relations):
        del_match2, del_tql2 = delete_sub_reln(reln, stix_object, var_name[0], i, import_type)
        del_match += del_match2
        del_tql += del_tql2

    # 4.0) Now setup the delete and match for the actual attributes, stix-id and object in reverse
    del_tql += '\n'
    del_tql += var_name[0] + ' isa ' + tql_name + ';\n'
    del_tql += '$a isa attribute;\n'
    del_tql += '$stix-id isa stix-id;\n'

    return del_match, del_tql


def delete_marking(stix_object, dep_match, dep_insert, indep_ql, core_ql, import_type) -> [str, str]:
    del_match = del_tql = ''
    if stix_object.definition_type == "statement":
        del_match = 'match \n$marking isa statement-marking'
        del_match += ',\n has stix-id $stix-id; $stix-id ' + val_tql(stix_object.id)
        del_match += ';\n$marking has $a;\n'
        del_match += 'not { $marking isa thing; $p2 isa thing, has $a; not {'
        del_match += '$marking is $p2;}; };\n\n'
        del_tql = 'delete \n'
        del_tql += '$marking isa statement-marking;\n'
        del_tql += '$stix-id isa stix-id;\n'
        del_tql += '$a isa attribute;\n'

    return del_match, del_tql


def get_obj_var(core_ql) -> List[str]:
    m = re.findall(r"(\$[a-z\-0-9]+)\s+(.+)?isa\s+", core_ql,re.MULTILINE)
    output = []
    #logger.debug(f'local 1 -> {m}')
    if m:
        #logger.debug(f'local -> {m}')
        for found in m:
            output.append(found[0])
            #logger.debug(f'Found first {found[0]}')

    return output


def get_tql_name(dep_insert):
    m = re.findall(r"([a-z\-]+),$",dep_insert,re.MULTILINE)
    output = []
    #logger.debug(f'local 1 -> {m}')
    if m:
        for found in m:
            output.append(found)
            #logger.debug(f'Found name {found}')

    return output


def delete_sub_reln(rel, obj, obj_var, i, import_type):
    """
        Top level function to delete one of the sub objects from the stix object
    Args:
        rel (): the relation object to delete
        obj (): the stix object to delete it from
        obj_var (): the typeql variable string

    Returns:
        match: the typeql match string
        delete: the typeql delete string
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    if rel == "granular_markings":
        match, delete = del_granular_markings(obj_var)

    # hashes type
    elif (rel == "hashes"
          or rel == "file_header_hashes"):
        match, delete = del_hashes(rel, obj[rel], obj_var, i)

    # insert key value store
    elif rel in auth["reln_name"]["key_value_relations"]:
        match, delete = del_key_value_store(rel, obj[rel], obj_var, i, import_type)

    # insert list of object relation
    elif rel in auth["reln_name"]["list_of_objects"]:
        match, delete = del_list_of_object(rel, obj[rel], obj_var, i, import_type)

    # insert embedded relations based on stix-id
    elif rel in auth["reln_name"]["embedded_relations"]:
        match, delete = del_embedded_relation(rel, obj[rel], obj_var, i, import_type)

    # insert plain sub-object with relation
    elif (rel == "x509_v3_extensions"
          or rel == "optional_header"):
        match, delete = del_load_object(rel, obj[rel], obj_var, i, import_type)

    # insert  SCO Extensions here, a possible dict of sub-objects
    elif rel == "extensions":
        match, delete = del_extensions(rel, obj[rel], obj_var, i, import_type)

    # ignore the following relations as they are already processed, for Relationships, Sightings and Extensions
    elif (rel == "sighting_of_ref"
          or rel == "observed_data_refs"
          or rel == "where_sighted_refs"
          or rel == "source_ref"
          or rel == "target_ref"
          or rel == "definition"
          or rel == "definition_type"):
        match = delete = ''

    else:
        logger.error(f'relation type not known, rel -> {rel}')
        match = delete = ""

    return match, delete


def del_granular_markings(obj_var):
    match = '$granular (object:' + obj_var + ') isa granular-marking;\n'
    delete = '$granular isa granular-marking;\n'

    return match, delete


def del_hashes(rel_name, rel_object, obj_var, i):
    match = '$hash isa hash, has hash-value $h;\n'
    match += '$hash_rel (hash-owner:'+obj_var
    match += ', hash-actual:$hash) isa hashes;\n'
    delete = '$hash_rel isa hashes;\n'
    delete += '$hash isa hash;\n'
    return match, delete


def del_key_value_store(rel_name, rel_object, obj_var, i, import_type):
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    for config in auth["reln"]["key_value_relations"]:
        if config["name"] == rel_name:
            rel_typeql = config["typeql"]
            role_owner = config["owner"]
            role_pointed = config["pointed_to"]
            d_key = config["key"]
            d_value = config["value"]
            break

    key_var = '$' + d_key + str(i)
    val_var = ' $' + d_value + str(i)
    match = key_var + ' isa ' + d_key + ';\n'
    match += key_var + ' has ' + d_value + val_var + ';\n'
    match += '$' + rel_typeql + ' (' + role_owner + ':' + obj_var
    match += ', ' + role_pointed + ':' + key_var
    match += ') isa ' + rel_typeql + ';\n\n'
    delete = '\n'
    delete += '$' + rel_typeql + ' isa ' + rel_typeql + ';\n'
    #delete += val_var + ' isa ' + d_value + ';\n'
    #delete += key_var + ' isa ' + d_key + ';\n'

    return match, delete


def del_list_of_object(rel_name, prop_value_list, parent_var, i, import_type):
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    logger.debug(f'rl name -> {rel_name}')
    for config in auth["reln"]["list_of_objects"]:
        if config["name"] == rel_name:
            rel_typeql = config["typeql"]
            role_owner = config["owner"]
            role_pointed = config["pointed_to"]
            typeql_obj = config["object"]
            obj_props_tql = copy.deepcopy(auth["sub_objects"][typeql_obj])
            break
    lod_list = []
    match = delete = ''
    for j, dict_instance in enumerate(prop_value_list):
        lod_var = '$' + typeql_obj + str(j)
        lod_list.append(lod_var)
        match += lod_var + ' isa ' + typeql_obj + ';\n'
        for key in dict_instance:
            typeql_prop = obj_props_tql[key]
            if typeql_prop == '':
                # split off for relation processing
                match2, delete2 = delete_sub_reln(key, dict_instance, lod_var, i + j, import_type)
                # then add it back together
                match = match + match2
                delete = delete + "\n" + delete2 + "\n"
        delete += lod_var + ' isa ' + typeql_obj + ';\n'

    loc_var = '$' + typeql_obj + str(i)
    #match += loc_var + ' isa ' + typeql_obj + ';\n'
    #match += loc_var + ' has $b' + str(i) + ';\n'
    #match += 'not { ' + loc_var + ' isa thing; $lob' + str(i) + ' isa thing, has $b' + str(i) + '; not {'
    #match += loc_var + ' is $lob' + str(i) + ';}; };\n\n'

    match += '\n $' + rel_typeql + str(i) + ' (' + role_owner + ':' + parent_var
    for lod_var in lod_list:
        match += ', ' + role_pointed + ':' + lod_var
    match += ') isa ' + rel_typeql + ';\n'

    #delete += loc_var + ' isa ' + typeql_obj + ';\n'
    #delete += '$b' + str(i) + ' isa attribute; \n'
    delete += '$' + rel_typeql + str(i) + ' isa ' + rel_typeql + ';\n'

    return match, delete


def del_embedded_relation(rel_name, rel_object, obj_var, i, import_type):
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    for ex in auth["reln"]["embedded_relations"]:
      if ex["rel"] == rel_name:
        owner = ex["owner"]
        relation = ex["typeql"]
        break
    loc_var = '$' + relation + str(i)
    match = loc_var + ' (' + owner + ':' + obj_var + ') isa ' + relation + ';\n'
    delete = loc_var + ' isa ' + relation + ';\n'

    return match, delete


def del_load_object(prop_name, prop_dict, parent_var, i, import_type):
    # as long as it is predefined, history the object
    #logger.debug('------------------- history object ------------------------------')
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    logger.debug(f'prop dict {prop_dict}')
    for prop_type in auth["reln"]["extension_relations"]:
        if prop_name == prop_type["stix"]:
            tot_prop_list = [tot for tot in prop_dict.keys()]
            obj_name = prop_type["object"]
            obj_tql = copy.deepcopy(auth["sub_objects"][obj_name])
            obj_var = '$' + obj_name
            reln = prop_type["relation"]
            rel_var = '$' + reln
            rel_owner = prop_type["owner"]
            rel_pointed_to = prop_type["pointed-to"]

            match = obj_var + ' isa ' + prop_type["object"] + ';\n'
            #match += obj_var + ' has $d' + str(i) + ';\n'
            #match += 'not { ' + obj_var + ' isa thing; $lobj' + str(i) + ' isa thing, has $d' + str(i) + '; not {'
            #match += obj_var + ' is $lobj' + str(i) + ';}; };\n\n'

            match += rel_var + ' (' + rel_owner + ':' + parent_var
            match += ', ' + rel_pointed_to + ':' + obj_var + ')'
            match += ' isa ' + reln + ';\n'

            # Split them into properties and relations
            properties, relations = split_on_activity_type(prop_dict, obj_tql)
            delete = ''

            # add each of the relations to the match and insert statements
            for rel in relations:
                # split off for relation processing
                match2, delete2= delete_sub_reln(rel, prop_dict, obj_var, i+1, import_type)
                # then add it back together
                match = match + match2
                delete = delete + "\n" + delete2

            # finally, connect the local object to the parent object
            #delete = '$d' + str(i) + ' isa attribute;\n'
            delete += rel_var + ' isa ' + reln + ';\n'
            delete += obj_var + ' isa ' + prop_type["object"] + ';\n'

            break

    return match, delete


def del_extensions(prop_name, prop_dict, parent_var, i, import_type):
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    match = ''
    delete = ''
    # for each key in the dict (extension type)
    # logger.debug('--------------------- extensions ----------------------------')
    for ext_type in prop_dict:
        for ext_type_ql in auth["reln"]["extension_relations"]:
            if ext_type == ext_type_ql["stix"]:
                match2, delete2 = del_load_object(ext_type, prop_dict[ext_type], parent_var, i, import_type)
                match = match + match2
                delete = delete + delete2
                break
    return match, delete


def add_delete_layers(layers, dep_obj, indexes, missing):
    logger.debug("################################### enter add_layers ###############################################")
    logger.debug(f'\nlayers -> {layers}')
    logger.debug(f'\ndep_obj -> {dep_obj}')
    logger.debug(f'indexes -> {indexes}')
    logger.debug(f'missing -> {missing}')
    logger.debug("-------------------------------  ------------------------------------------------")
    # Stage 1 - Initialise Variables
    # 1. Setup key variables
    loc_id = dep_obj['id']
    loc_list = dep_obj["dep_list"]
    locset = set(loc_list)
    mset = set(missing)
    iset = set(indexes)
    intset = locset.intersection(iset)
    diffset = locset.difference(intset)
    # Stage 2 - Analyse Choices
    # 2. check whether the object has dependencies in its dep_list
    if not loc_list:
        dep_list_items = False
        logger.debug('### There are no dependencies')
    else:
        dep_list_items = True
        logger.debug('### There are some dependencies')
    # 3. check whether the object id is in the missing list
    if loc_id in mset:
        id_in_missing = True
        logger.debug('### Current is the missing dependency of an existing record')
    else:
        id_in_missing = False
        logger.debug('### Current is not a missing dependency of an existing record')
    # 4. check whether any id in the object dependency list is not already loaded
    if not diffset:
        dep_id_not_loaded = False
        logger.debug('### No dependencies need to be added to missing')
    else:
        dep_id_not_loaded = True
        mset = mset | diffset
        logger.debug('### Missing - Some dependencies need to be added to missing')

    # Stage 3 - Execute Choices
    # 5. No dependencies and not in missing, append only
    if not dep_list_items and not id_in_missing:
        logger.debug('### Append object and return')
        layers.append(dep_obj)
        indexes.append(loc_id)
        logger.debug(f'layers -> {layers}')
        logger.debug(f'indexes -> {indexes}')
        logger.debug(f'mset -> {mset}')
        logger.debug("################################## end of  add_layers ####################################################")
        return layers, indexes, list(mset)
    # 6. There are no dependencies but id is in missing, delete from missing,follow the tree and reorder
    if not dep_list_items and id_in_missing:
        logger.debug('### delete from missing,follow the tree and reorder')
        mset.remove(loc_id)
        tree = follow_the_tree(layers, dep_obj)
        logger.debug(f' tree -> {tree}')
        layers, indexes = reorder(layers, indexes, tree, dep_obj)
        logger.debug(f'layers -> {layers}')
        logger.debug(f'indexes -> {indexes}')
        logger.debug(f'mset -> {mset}')
        logger.debug("################################## end of  add_layers ####################################################")
        return layers, indexes, list(mset)
    # 7 There are dependencies, object is not in missing, insert at front
    if dep_list_items and not id_in_missing:
        logger.debug('### Add current to the front of the record')
        layers.insert(0, dep_obj)
        indexes.insert(0, loc_id)
        logger.debug(f'layers -> {layers}')
        logger.debug(f'indexes -> {indexes}')
        logger.debug(f'mset -> {mset}')
        logger.debug("################################## end of  add_layers ####################################################")
        return layers, indexes, list(mset)
    # 8 There are dependencies, object is in missing , delete from missing,follow the tree and reorder
    if dep_list_items and id_in_missing:
        logger.debug('### delete from missing,follow the tree and reorder')
        mset.remove(loc_id)
        tree = follow_the_tree(layers, dep_obj)
        logger.debug(f' tree -> {tree}')
        layers, indexes = reorder(layers, indexes, tree, dep_obj)
        logger.debug(f'layers -> {layers}')
        logger.debug(f'indexes -> {indexes}')
        logger.debug(f'mset -> {mset}')
        logger.debug("################################## end of  add_layers ####################################################")
        return layers, indexes, list(mset)

    logger.debug("theres a massive problem")
    return layers, indexes, list(mset)


def reorder(layers, indexes, tree, dep_obj):
    front_layers = []
    front_indexes = []
    tree = list(set(tree))
    logger.debug("%%%%%%%%%%%%%%% reorder 1 %%%%%%%%%%%%%%%%%%")
    logger.debug(f'\n orig indexes -> {indexes}')
    logger.debug(f"\n orig layers, {layers}")
    logger.debug(f"\n dep_obj , {dep_obj}")
    logger.debug("%%%%%%%%%%%%%%% reorder 2 %%%%%%%%%%dep_obj%%%%%%%%")
    # 1. Copy elements from layers and indexes so they are in the order we want them
    for t in reversed(tree):
        front_layers.append(layers[t])
        front_indexes.append(indexes[t])
    # 2. Now order the tree in reverse numeric order, biggest first
    tree.sort(reverse=True)
    # 3. Now delete the elements from layers and indexes
    for t in tree:
        layers.pop(t)
        indexes.pop(t)
    # 4. Add the dep_obj to the new lists
    front_indexes.append(dep_obj['id'])
    front_layers.append(dep_obj)
    # 5. Assemble the final lists
    logger.debug(f'\nfront_indexes -> {front_indexes}')
    logger.debug(f"\nfront_layers, {front_layers}")
    logger.debug(f"\n old layers, {layers}")
    logger.debug(f'\nold indexes -> {indexes}')
    logger.debug("-------------------------------------------------------------------------------------")
    layers = front_layers + layers
    indexes = front_indexes + indexes
    #logger.debug(f"\nlayers, {layers}")
    #logger.debug(f'\nindexes -> {indexes}')
    logger.debug("%%%%%%%%%%%%%%% end reorder %%%%%%%%%%%%%%%%%%")
    return layers, indexes


def follow_the_tree(layers, dep_obj):
    tree = []
    loc_id = dep_obj['id']
    loc_ids = [loc_id]
    found = True
    while found:
        found, ret_indexes, ret_ids = find_id(loc_ids, layers)
        logger.debug(f'### Following Tree, found {found},index {ret_indexes}, loc_id {ret_ids}')
        if found:
            tree = tree + ret_indexes
            loc_ids = ret_ids
    return tree


def find_id(loc_ids, layers) -> [bool, List[int], List[str]]:
    found = False
    indexes = []
    ids = []
    for loc_id in loc_ids:
        for index, lay in enumerate(layers):
            if loc_id in lay['dep_list']:
                found = True
                indexes.append(index)
                ids.append(lay['id'])

    return found, indexes, ids



