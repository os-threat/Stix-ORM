
import json
import copy
import importlib.util
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stix2.exceptions import ParseError
from stix2.parsing import dict_to_stix2
import logging

from stixorm.module.parsing.content.parse import determine_content_object_from_list_by_tests, ParseContent

from stixorm.module.typedb_lib.factories.auth_factory import get_auth_factory_instance
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType

logger = logging.getLogger(__name__)
default_import_type = import_type_factory.get_default_import()


def resolve_class_from_name(class_name: str, content_record: ParseContent):
    """
    Resolve a class name string to the actual class object.
    
    Args:
        class_name (str): The name of the class to resolve
        content_record (ParseContent): The content record containing protocol information
        
    Returns:
        class: The resolved class object
        
    Raises:
        ParseError: If the class cannot be resolved
    """
    try:
        # Determine which module to import from based on the protocol
        protocol = content_record.protocol
        
        if protocol == "stix21":
            # Try importing from stix2 first
            try:
                import stix2
                return getattr(stix2, class_name)
            except AttributeError:
                pass
                
        elif protocol == "os-threat":
            # Import from os-threat classes
            from stixorm.module.definitions.os_threat import classes
            return getattr(classes, class_name)
            
        elif protocol == "attack":
            # Import from attack classes
            from stixorm.module.definitions.attack import classes
            return getattr(classes, class_name)
            
        elif protocol == "oca":
            # Import from oca classes  
            from stixorm.module.definitions.oca import classes
            return getattr(classes, class_name)
            
        elif protocol == "mbc":
            # Import from mbc classes
            from stixorm.module.definitions.mbc import classes
            return getattr(classes, class_name)
            
        # If not found in protocol-specific module, try stix2 as fallback
        try:
            import stix2
            return getattr(stix2, class_name)
        except AttributeError:
            pass
            
        raise ParseError(f"Could not resolve class '{class_name}' for protocol '{protocol}'")
        
    except ImportError as e:
        raise ParseError(f"Could not import module for protocol '{protocol}': {e}")
    except AttributeError as e:
        raise ParseError(f"Class '{class_name}' not found in protocol '{protocol}' module: {e}")


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
    if 'type' not in stix_dict:
        raise ParseError(f"Can't parse object with no 'type' property: {str(stix_dict)}")
    logger.debug(f"I'm in dict to stix, {stix_dict}")
    # 2. get content record
    content_record: ParseContent = determine_content_object_from_list_by_tests(stix_dict=stix_dict, content_type="class")
    
    # Check if content_record was found
    if content_record is None:
        raise ParseError(f"No matching content record found for type: {stix_dict.get('type', 'unknown')}")
    
    # Get the class name from the content record
    logger.debug(f'content_record is {content_record}')
    class_name = content_record.python_class
    
    # Resolve the class name to the actual class object
    obj_class = resolve_class_from_name(class_name, content_record)
    
    return obj_class(**stix_dict)
