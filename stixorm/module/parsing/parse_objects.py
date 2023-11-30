
import json
import copy
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stix2.exceptions import ParseError
from stix2.parsing import dict_to_stix2
from stixorm.module.parsing.conversion_decisions import sdo_type_to_tql, sro_type_to_tql
import logging

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType

logger = logging.getLogger(__name__)
default_import_type = import_type_factory.get_default_import()



def parse(data: dict, allow_custom=False, import_type: ImportType=default_import_type):
    """Convert a string, dict or file-like object into a STIX object.
    Args:
        data (str, dict, file-like object): The STIX 2 content to be parsed.
        allow_custom (bool): Whether to allow custom properties as well unknown
            custom objects. Note that unknown custom objects cannot be parsed
            into STIX objects, and will be returned as is. Default: False.
        import_type (dict): If present, it describes the set of configuration
            options, which impact the classes the parser will see
    Returns:
        An instantiated Python STIX object.
    Warnings:
        'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types
        (both STIX2 domain objects or defined custom STIX2 objects); NO
        validation is done. This is done to allow the processing of possibly
        unknown custom STIX objects (example scenario: I need to query a
        third-party TAXII endpoint that could provide custom STIX objects that
        I don't know about ahead of time)
    """
    # convert STIX object to dict, if not already
    logger.debug("i'm in parse, bout to get dict")
    obj = _get_dict(data)
    logger.debug("i'm in parse after get dict")

    # convert dict to full python-stix2 obj
    obj = dict_to_stix(obj, allow_custom, import_type)
    logger.debug(f"############## obj is {obj} ########")

    return obj


def _get_dict(data):
    """Return data as a dictionary.
    Input can be a dictionary, string, or file-like object.
    """

    if type(data) is dict:
        return data
    else:
        try:
            return json.loads(data)
        except TypeError:
            pass
        try:
            return json.load(data)
        except AttributeError:
            pass
        try:
            return dict(data)
        except (ValueError, TypeError):
            raise ValueError(f"Cannot convert {str(data)} to dictionary.")


def is_attack_object(stix_dict):
    if stix_dict.get("x_mitre_domains", False) or stix_dict.get("x_mitre_attack_spec_version", False):
        return True
    else:
        return False


def dict_to_stix(stix_dict: dict,
                 allow_custom=False,
                 import_type: ImportType=default_import_type):
    """convert dictionary to full python-stix2 object
    Args:
        stix_dict (dict): a python dictionary of a STIX object
            that (presumably) is semantically correct to be parsed
            into a full python-stix2 obj
        allow_custom (bool): Whether to allow custom properties as well
            unknown custom objects. Note that unknown custom objects cannot
            be parsed into STIX objects, and will be returned as is.
            Default: False.
        import_type (dict): If present, it describes the set of configuration
            options, which impact the classes the parser will see
    Returns:
        An instantiated Python STIX object
    Warnings:
        'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types
        (both STIX2 domain objects or defined custom STIX2 objects); NO
        validation is done. This is done to allow the processing of
        possibly unknown custom STIX objects (example scenario: I need to
        query a third-party TAXII endpoint that could provide custom STIX
        objects that I don't know about ahead of time)
    """
    assert len(stix_dict) > 0
    logger.debug(f"I'm in dict to stix, {stix_dict}")
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    if 'type' not in stix_dict:
        raise ParseError(f"Can't parse object with no 'type' property: {str(stix_dict)}")

    obj_type = stix_dict["type"]
    logger.debug(f'\nin parse, raw type is --> {obj_type}')
    logger.debug(f'\n auth-sdo -->{auth["tql_types"]["sdo"]}\n')
    logger.debug(f'\n\n auth-sro -->{auth["tql_types"]["sro"]}\n')
    attack_object = is_attack_object(stix_dict)
    logger.debug(f'attack object {attack_object}')
    #logger.info(f'auth is {auth["tql_types"]["meta"]}')
    if obj_type in auth["types"]["sdo"]:
        logger.debug("Im in sdo")
        step_type = ""
        if obj_type == "sequence":
            step_type = stix_dict["step_type"]
        sub_technique = False
        if attack_object:
            sub_technique = stix_dict.get("x_mitre_is_subtechnique", False)
        logger.debug(f'subtechnique {sub_technique}, attack {attack_object}')
        obj_tql, sdo_tql_name, is_list, protocol = sdo_type_to_tql(obj_type, import_type, attack_object, sub_technique, step_type)
        logger.debug(f"tql name {sdo_tql_name}, obj tql {obj_tql}")
        obj_class = class_for_type(sdo_tql_name, import_type, "sdo")
        logger.debug(f'output  object class is {obj_class}')
    elif obj_type in auth["types"]["sco"]:
        logger.debug("I'm in sco")
        obj_class = class_for_type(obj_type, import_type, "sco")
    elif obj_type in auth["types"]["sro"]:
        logger.debug("I'm in sro")
        uses_relation = False
        is_procedure = False
        if attack_object:
            uses_relation = False if not stix_dict.get("relationship_type", False) == "uses" else True
            is_procedure = False if not stix_dict.get("target_ref", False) == "attack-pattern" else True
        obj_tql = {}
        sro_sub_rel = "" if not stix_dict.get("relationship_type", False) else stix_dict["relationship_type"]

        obj_tql, sro_tql_name, is_list, protocol = sro_type_to_tql(obj_type, sro_sub_rel, import_type, attack_object,
                                                         uses_relation, is_procedure)
        logger.debug(f"~~~~~~~~~~~ sro tql name {sro_tql_name}")
        if obj_type == "relationship":
            if attack_object:
                obj_tql_name = "attack-relation"
            else:
                obj_tql_name = "stix-core-relationship"
        elif obj_type == "sighting":
            obj_tql_name = "sighting"
        if sro_tql_name == "attack-relation":
            obj_tql_name = sro_tql_name
        obj_class = class_for_type(obj_tql_name, import_type, "sro")
    elif obj_type in auth["types"]["sub"]:
        logger.debug("I'm in sub")
        obj_class = class_for_type(obj_type, import_type, "sub")
    elif obj_type in auth["types"]["meta"]:
        logger.debug("I'm in meta")
        if attack_object:
            obj_class = class_for_type("attack-marking", import_type, "meta")
        else:
            obj_class = dict_to_stix2(stix_dict, True)
            logger.debug(f'object class is finally {obj_class}')
            return obj_class

    elif allow_custom:
        logger.debug("I'm in custom")
        raise ParseError(f'the object is not known, and custom is enabled but not implemented')
    else:
        logger.debug("object is not known")
        raise ParseError(f'the object is not known, and custom is not enabled')

    if not obj_class:
        if allow_custom:
            # flag allows for unknown custom objects too, but will not
            # be parsed into STIX object, returned as is
            return stix_dict
        for key_id, ext_def in stix_dict.get('extensions', {}).items():
            if (
                key_id.startswith('extension-definition--') and
                'property-extension' not in ext_def.get('extension_type', '')
            ):
                # prevents ParseError for unregistered objects when
                # allow_custom=False and the extension defines a new object
                return stix_dict
        raise ParseError(f"Can't parse unknown object type {obj_type}! For custom types, use the CustomObject decorator." + str(obj_type))

    logger.debug(f'object class is finally {obj_class}')
    logger.debug("========================================")
    for k, v in stix_dict.items():
        logger.debug(f'k-> {k}, v->{v}')
    logger.debug("=========================================")
    stix_dict['allow_custom'] = allow_custom
    return obj_class(**stix_dict)


def class_for_type(stix_typeql, import_type, category=None):
    """
    Get the registered class which implements a particular STIX type for a
    particular STIX version.
    :param stix_typeql: A STIX type as a string, or for extension-definition
        style extensions, the STIX ID of the definition.
    :param import_type: If present, it describes the set of configuration
            options, which impact the classes the parser will see
    :param category: An optional "category" value, which is just used directly
        as a second key after the STIX version, and depends on how the types
        are internally categorized.  This would be useful if the same STIX type
        is used to mean two different things within the same STIX version.  So
        it's unlikely to be necessary.  Pass None to just search all the
        categories and return the first class found.
    :return: A registered python class which implements the given STIX type, or
        None if one is not found.
    """
    auth_factory = get_auth_factory_instance()
    auth = auth_factory.get_auth_for_import(import_type)
    conv_cls = ""
    cls = None
    logger.debug(f' working out classes, typeql {stix_typeql}, category {category}')

    # find the conversion record
    if category is not None:
        for obj in auth["conv"][category]:
            logger.debug(f'object tql is {obj["typeql"]}, wanted {stix_typeql}')
            if obj["typeql"] == stix_typeql:
                logger.debug("found the right type")
                conv_cls = obj["class"]
                logger.debug(f'classs is {conv_cls}')
                cls = copy.deepcopy(auth["classes"][category][conv_cls])
                logger.debug(f'classs 2 is {cls}')
                return cls

    return cls
