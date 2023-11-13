import json
import os
import uuid
import copy
from enum import Enum
from typing import Optional
from stix2.properties import Property
from stix2.utils import STIXTypeClass
from stix2.exceptions import CustomContentError
from stix2.base import _STIXBase
from stix2.properties import (
    DictionaryProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, ObservableProperty
)

from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

DEFAULT_VERSION = '2.1'
ERROR_INVALID_ID = (
    "not a valid STIX identifier, must match <object-type>--<UUID>: {}"
)


# TODO: Kestrel was missing from original definition, does this need to be fixed?
def get_libraries():
    return ["stix", "attack", "os-threat", "cacao"]


def get_type_from_id(stix_id):
    return stix_id.split('--', 1)[0]


def _check_uuid(uuid_str, spec_version):
    """
    Check whether the given UUID string is valid with respect to the given STIX
    spec version.  STIX 2.0 requires UUIDv4; 2.1 only requires the RFC 4122
    variant.
    :param uuid_str: A UUID as a string
    :param spec_version: The STIX spec version
    :return: True if the UUID is valid, False if not
    :raises ValueError: If uuid_str is malformed
    """
    uuid_obj = uuid.UUID(uuid_str)

    ok = uuid_obj.variant == uuid.RFC_4122
    if ok and spec_version == "2.0":
        ok = uuid_obj.version == 4

    return ok


def _validate_id(id_, spec_version, required_prefix):
    """
    Check the STIX identifier for correctness, raise an exception if there are
    errors.
    :param id_: The STIX identifier
    :param spec_version: The STIX specification version to use
    :param required_prefix: The required prefix on the identifier, if any.
        This function doesn't add a "--" suffix to the prefix, so callers must
        add it if it is important.  Pass None to skip the prefix check.
    :raises ValueError: If there are any errors with the identifier
    """
    if required_prefix:
        if not id_.startswith(required_prefix):
            raise ValueError("must start with '{}'.".format(required_prefix))

    try:
        if required_prefix:
            uuid_part = id_[len(required_prefix):]
        else:
            idx = id_.index("--")
            uuid_part = id_[idx+2:]

        result = _check_uuid(uuid_part, spec_version)
    except ValueError:
        # replace their ValueError with ours
        raise ValueError(ERROR_INVALID_ID.format(id_))

    if not result:
        raise ValueError(ERROR_INVALID_ID.format(id_))


def is_stix_type(obj_type, spec_version, valid_types):
    if obj_type in valid_types:
        return True
    else:
        return False


class ThreatReference(Property):

    _WHITELIST, _BLACKLIST = range(2)

    def __init__(self, valid_types=None, invalid_types=None, spec_version=DEFAULT_VERSION, **kwargs):
        """
        references sometimes must be to a specific object type
        """
        self.spec_version = spec_version

        if (valid_types is not None and invalid_types is not None) or \
                (valid_types is None and invalid_types is None):
            raise ValueError(
                "Exactly one of 'valid_types' and 'invalid_types' must be "
                "given",
            )

        if valid_types and not isinstance(valid_types, list):
            valid_types = [valid_types]
        elif invalid_types and not isinstance(invalid_types, list):
            invalid_types = [invalid_types]

        if valid_types is not None and len(valid_types) == 0:
            raise ValueError("Impossible type constraint: empty whitelist")

        # Divide type requirements into generic type classes and specific
        # types.  With respect to strings, values recognized as STIXTypeClass
        # enum names are generic; all else are specifics.
        self.valid_types = valid_types
        self.invalid_types = invalid_types

        super(ThreatReference, self).__init__(**kwargs)

    def clean(self, value, allow_custom):
        if isinstance(value, _STIXBase):
            value = value.id
        value = str(value)

        _validate_id(value, self.spec_version, None)

        obj_type = get_type_from_id(value)

        type_ok = is_stix_type(obj_type, self.spec_version, self.valid_types)

        if not type_ok:
            raise ValueError(
                "The type-specifying prefix '%s' for this property is %s"
                % obj_type,
            )

        return value, False



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



class ThreatExtensionsProperty(DictionaryProperty):
    """Property for representing extensions on Observable objects.
    """

    def __init__(self, spec_version=DEFAULT_VERSION, required=False):
        super(ThreatExtensionsProperty, self).__init__(spec_version=spec_version, required=required)

    def clean(self, value, allow_custom):
        try:
            dictified = _get_dict(value)
            # get deep copy since we are going modify the dict and might
            # modify the original dict as _get_dict() does not return new
            # dict when passed a dict
            dictified = copy.deepcopy(dictified)
        except ValueError:
            raise ValueError("The extensions property must contain a dictionary")

        has_custom = False
        for key, subvalue in dictified.items():
            cls = get_mapping_factory_instance().get_ext_class(key, 'os_threat')
            if cls:
                if isinstance(subvalue, dict):
                    ext = cls(allow_custom=False, **subvalue)
                elif hasattr(cls, '_type') and hasattr(subvalue, '_type') and cls._type == subvalue._type:
                    ext = subvalue
                elif isinstance(subvalue, cls):
                    # If already an instance of the registered class, assume
                    # it's valid
                    ext = subvalue
                else:
                    raise TypeError(
                        "Can't create extension '{}' from {}.".format(
                            key, type(subvalue),
                        ),
                    )

                has_custom = has_custom or ext.has_custom

                if not allow_custom and has_custom:
                    raise CustomContentError(
                        "custom content found in {} extension".format(
                            key,
                        ),
                    )

                dictified[key] = ext

            else:
                # If an unregistered "extension-definition--" style extension,
                # we don't know what's supposed to be in it, so we can't
                # determine whether there's anything custom.  So, assume there
                # are no customizations.  If it's a different type of extension,
                # non-registration implies customization (since all spec-defined
                # extensions should be pre-registered with the library).

                if key.startswith('extension-definition--'):
                    _validate_id(
                        key, self.spec_version, 'extension-definition--',
                    )
                elif allow_custom:
                    has_custom = True
                else:
                    raise CustomContentError("Can't parse unknown extension type: {}".format(key))

                dictified[key] = subvalue

        return dictified, has_custom
