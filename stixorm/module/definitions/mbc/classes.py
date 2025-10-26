"""Python Mitre ATT&CK Stix Class Definitions """
from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

"""Python Mitre ATT&CK Stix Class Definitions """
import json
import pathlib
import warnings
from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, STIXDeprecationWarning, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, DictionaryProperty, EnumProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, ObservableProperty, HexProperty, HashesProperty
)
from stix2.utils import NOW, _get_dict
from stix2.markings import _MarkingsMixin
from stix2.markings.utils import check_tlp_marking
from stix2.v21.base import _DomainObject, _STIXBase21, _RelationshipObject, _Extension, _Observable
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
    MarkingProperty, TLPMarking, StatementMarking,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, IDENTITY_CLASS, INDUSTRY_SECTOR, REPORT_TYPE,HASHING_ALGORITHM,
    EXTENSION_TYPE
)

import logging

from stixorm.module.definitions.property_definitions import OSThreatReference, OSThreatExtensionsProperty


logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()



##################################################################################
#       SDO
##################################################################################

class ObjDefinition(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_72bcfr3t79jx>`__.
    """

    _properties = OrderedDict([
        ('source_name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('url', StringProperty()),
        ('hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
        ('external_id', StringProperty()),
    ])

    # This is hash-algorithm-ov
    _LEGAL_HASHES = {
        "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "SSDEEP",
        "TLSH",
    }

    def _check_object_constraints(self):
        super(ObjDefinition, self)._check_object_constraints()
        self._check_at_least_one_property(['description', 'external_id', 'url'])

        if "hashes" in self:
            if any(
                hash_ not in self._LEGAL_HASHES
                for hash_ in self["hashes"]
            ):
                raise InvalidValueError(
                    ExternalReference, "hashes",
                    "Hash algorithm names must be members of hash-algorithm-ov",
                )



class Snippet(_STIXBase21):
    """For more detailed information on this object's properties, see
    `https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/malware-behavior-8e9`__.
    """
    _type = 'snippet'
    _properties = OrderedDict([
        ('snippet', StringProperty(required=True)),
        ('exemplify_ref', OSThreatReference(valid_types='malware-method', spec_version='2.1')),
        ('language', OpenVocabProperty(IMPLEMENTATION_LANGUAGE)),
        ('description', StringProperty()),
        ('references', ListProperty(ExternalReference)),
        ('hash', StringProperty()),
        ('author_ref', ReferenceProperty(valid_types='identity', spec_version='2.1'))
    ])
    

class DetectionRule(_STIXBase21):
    """For more detailed information on this object's properties, see
    `https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/malware-behavior-8e9`__.
    """
    _type = 'detection-rule'
    _properties = OrderedDict([
        ('rule_type', StringProperty(required=True)),
        ('rule_name', StringProperty()),
        ('rule', StringProperty()),
        ('url', StringProperty()),
        ('detect_ref', OSThreatReference(valid_types='malware-method', spec_version='2.1')),
        ('description', StringProperty()),
        ('detection-rule', ListProperty(StringProperty)),
        ('api_fncs', ListProperty(StringProperty)),
        ('class', StringProperty()),  # Added to support class field in MBC data
    ])


class MBCExtension(_Extension):
    """For more detailed information on this object's properties, see
    `the __.
    """

    _type = 'extension-definition--d57b7c9c-7fa6-436b-b82c-8e6f69cdc3d0'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo'))
    ])



class MalwareBehavior(_DomainObject):
    """For more detailed information on this object's properties, see
    `https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/malware-behavior-8e9`__.
    """

    _type = 'malware-behavior'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('micro', BooleanProperty(default=lambda: False)),
        ('obj_defn', EmbeddedObjectProperty(type=ObjDefinition)), 
        ('obj_version', StringProperty()),
        ('related_object_refs', ListProperty(ReferenceProperty(valid_types='attack-pattern', spec_version='2.1'))),
        ('tags', DictionaryProperty(spec_version='2.1')),
        ('objective_refs', ListProperty(OSThreatReference(valid_types='malware-objective', spec_version='2.1'))),
        ('snippets', ListProperty(EmbeddedObjectProperty(type=Snippet))),
        ('detection_rules', ListProperty(EmbeddedObjectProperty(type=DetectionRule))),
        ('contributor_refs', ListProperty(ReferenceProperty(valid_types='identity', spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])





class MalwareMethod(_DomainObject):
    """For more detailed information on this object's properties, see
    `https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/malware-behavior-8e9`__.
    """

    _type = 'malware-method'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('micro', BooleanProperty(default=lambda: False)),
        ('obj_defn', EmbeddedObjectProperty(type=ObjDefinition)), 
        ('behavior_ref', OSThreatReference(valid_types='malware-behavior', spec_version='2.1')),
        ('contributor_refs', ListProperty(ReferenceProperty(valid_types='identity', spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])


 


class MalwareObjective(_DomainObject):
    """For more detailed information on this object's properties, see
    `https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/malware-behavior-8e9`__.
    """

    _type = 'malware-objective'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('micro', BooleanProperty(default=lambda: False)),
        ('obj_defn', EmbeddedObjectProperty(type=ObjDefinition)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', OSThreatExtensionsProperty(spec_version='2.1')),
    ])




class MalwareExt(_Extension):
    """For more detailed information on this object's properties, see
    `the __.
    """

    _type = 'extension-definition--8e9e338f-c9ee-4d4f-8cac-85b4dcfdf3c1'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('obj_defn', EmbeddedObjectProperty(type=ObjDefinition)),
        ('year', StringProperty()),
        ('platforms', ListProperty(StringProperty)),
    ])

