
import json
from stix2.parsing import dict_to_stix2
from stix.module.authorise import authorised_mappings, default_import_type
from stix2.exceptions import ParseError
from stix.module.orm.conversion_decisions import sdo_type_to_tql, sro_type_to_tql, sco__type_to_tql


def parse(data, allow_custom=False, import_type=default_import_type):
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
    print("i'm in parse, bout to get dict")
    obj = _get_dict(data)
    print("i'm in parse after get dict")

    # convert dict to full python-stix2 obj
    obj = dict_to_stix2(obj, allow_custom, import_type)
    print(f"############## obj is {obj} ########")

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
            raise ValueError("Cannot convert '%s' to dictionary." % str(data))


def dict_to_stix2(stix_dict, allow_custom=False, import_type=default_import_type):
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
    print("I'm in dict to stix")
    auth = authorised_mappings(import_type)
    if 'type' not in stix_dict:
        raise ParseError("Can't parse object with no 'type' property: %s" % str(stix_dict))

    version = "2.1"
    print(f"my version is {version}")
    print(f'my type is {stix_dict["type"]}')
    # if stix_dict["version"] != "2.1":
    #     print("I am exiting because of my version number")
    #     raise ParseError("Can't parse versions other than v2.1 '%s'! For custom types, use the CustomObject decorator." % stix_dict["version"])

    obj_type = stix_dict["type"]
    print(f'\nin parse, type is --> {obj_type}')
    print(f'\n auth-sdo -->{auth["tql_types"]["sdo"]}\n')
    if obj_type in auth["tql_types"]["sdo"]:
        print("Im in sdo")
        attack_object = False if not stix_dict.get("x_mitre_version", False) else True
        sub_technique = False
        if attack_object:
            sub_technique = False if not stix_dict.get("x_mitre_is_subtechnique", False) else True
        print(f'subtechnique {sub_technique}, attack {attack_object}')
        obj_tql, sdo_tql_name, is_list = sdo_type_to_tql(obj_type, import_type, attack_object, sub_technique)
        print(f"tql name {sdo_tql_name}, obj tql {obj_tql}")
        obj_class = class_for_type(sdo_tql_name, import_type, "sdo")
        print(f'output  object class is {obj_class}')
    elif obj_type in auth["tql_types"]["sco"]:
        print("I'm in sco")
        obj_class = class_for_type(obj_type, import_type, "sco")
    elif obj_type in auth["tql_types"]["sro"]:
        print("I'm in sro")
        uses_relation = False
        is_procedure = False
        attack_object = False if not stix_dict.get("x_mitre_version", False) else True
        if attack_object:
            uses_relation = False if not stix_dict.get("relationship_type", False) == "uses" else True
            is_procedure = False if not stix_dict.get("target_ref", False) == "attack-pattern" else True
        obj_tql = {}
        sro_sub_rel = "" if not stix_dict.get("relationship_type", False) else stix_dict["relationship_type"]

        obj_tql, sro_tql_name, is_list = sro_type_to_tql(obj_type, sro_sub_rel, import_type, attack_object,
                                                         uses_relation, is_procedure)

        obj_class = class_for_type(obj_type, import_type, "sro")
    elif obj_type in auth["tql_types"]["sub"]:
        print("I'm in sub")
        obj_class = class_for_type(obj_type, import_type, "sub")
    elif allow_custom:
        print("I'm in custom")
        raise ParseError(f'the object is not known, and custom is enabled but not implemented')
    else:
        print("object is not known")
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
        raise ParseError("Can't parse unknown object type '%s'! For custom types, use the CustomObject decorator." % obj_type)

    print(f'object class is finally {obj_class}')
    return obj_class(allow_custom, **stix_dict)


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
    auth = authorised_mappings(import_type)
    conv_cls = ""
    cls = None
    print(f' working out calsses, typeql {stix_typeql}, category {category}')

    # find the conversion record
    if category is not None:
        for obj in auth["conv"][category]:
            print(f'object tql is {obj["typeql"]}, wanted {stix_typeql}')
            if obj["typeql"] == stix_typeql:
                print("found the right type")
                conv_cls = obj["class"]
                print(f'classs is {conv_cls}')
                cls = auth["classes"][category][conv_cls]
                print(f'classs 2 is {cls}')
                return cls

    return cls
