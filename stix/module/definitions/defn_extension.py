import json
import pathlib
import os
import uuid
import copy


from stix2.exceptions import CustomContentError
from stix2.properties import (
    DictionaryProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, ObservableProperty
)

from stix.module.definitions.definitions import get_definitions, _validate_id
# from stix.module.definitions.os_threat.classes import (
#     EventCoreExt, ImpactCoreExt, Availability, Confidentiality,
#     External, Integrity, Monetary, Physical, Traceability,
#     IncidentCoreExt, TaskCoreExt,
#     EvidenceCoreExt
# )

DEFAULT_VERSION = '2.1'

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


def get_ext_class(key, spec_version):
    defin = get_definitions()
    list_of_ext = defin.sub_objects
    for ext in list_of_ext:
        if ext["type"] == key:
            return ext["class"]


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
            cls = get_ext_class(key, self.spec_version)
            if cls:
                if isinstance(subvalue, dict):
                    ext = cls(allow_custom=False, **subvalue)
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
