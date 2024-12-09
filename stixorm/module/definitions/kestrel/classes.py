"""Python CACAO Stix Class Definitions """

import json
import pathlib
from collections import OrderedDict

from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, FloatProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, DictionaryProperty,
    HashesProperty
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
    PROCESSOR_ARCHITECTURE, TOOL_TYPE,
)


import logging

from stixorm.module.definitions.property_definitions import ThreatReference, ThreatExtensionsProperty


logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()
# i) allows x- prefix see properties.py line 592 obj_type.startswith("x-") and
# ii) allows non stix definitiosn to be added see properties.py line 592 is_object(obj_type, self.spec_version)


############################################################################################
#
# SDO Definitions
#
############################################################################################


class BehaviorExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-behavior.md`__.
    """

    _type = "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62"
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Behavior(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OCA documentation  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-behavior.md`__.
    """
    _type = 'x-oca-behavior'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('tactic', StringProperty()),
        ('technique', StringProperty()),
        ('first_seen', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('platforms',  DictionaryProperty(spec_version='2.1')),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])



class CoAPlayookExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-coa-playbook-ext.md
    """

    _type = 'extension-definition--bbc1d5c8-7ddc-4e89-be9c-f33ad02d71dd'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension')),
        ('playbooks ', DictionaryProperty(spec_version='2.1')),
    ])


class PlaybookExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-playbook.md`__.
    """

    _type = "extension-definition--809c4d84-7a6e-4039-97b4-da9fea03fcf9"
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Playbook(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OCA documentation  https://github.com/os-threat/oca-stix-extensions/blob/main/2.x/SDO/x-oca-playbook.md
    """
    _type = 'x-oca-playbook'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('playbook_id', StringProperty()),
        ('playbook_creator', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('playbook_creation_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('playbook_modification_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('playbook_format',  ListProperty(StringProperty)),
        ('is_playbook_template', BooleanProperty()),
        ('playbook_type', ListProperty(StringProperty)),
        ('playbook_impact', IntegerProperty()),
        ('playbook_severity', IntegerProperty()),
        ('playbook_priority', IntegerProperty()),
        ('playbook_bin', StringProperty()),
        ('playbook_url', StringProperty()),
        ('playbook_hashes', HashesProperty(HASHING_ALGORITHM, spec_version="2.1")),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

