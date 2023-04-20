"""Python Mitre ATT&CK Stix Class Definitions """

"""Python Mitre ATT&CK Stix Class Definitions """
import json
import pathlib
from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty
)
from stix2.utils import NOW, _get_dict
from stix2.markings import _MarkingsMixin
from stix2.markings.utils import check_tlp_marking
from stix2.v21.base import _DomainObject, _STIXBase21, _RelationshipObject
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
    MarkingProperty, TLPMarking, StatementMarking,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, IDENTITY_CLASS, INDUSTRY_SECTOR,
)

import logging

from stix.module.definitions.definitions import get_definitions, ThreatReference
from stix.module.typedb_lib.auth_types import all_auth_types

logger = logging.getLogger(__name__)

valid_obj =  list(get_definitions().get_all_types())
# i) allows x- prefix see properties.py line 592 obj_type.startswith("x-") and
# ii) allows non stix definitiosn to be added see properties.py line 592 is_object(obj_type, self.spec_version)
class ThreatSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class Feed(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'feed'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('paid', BooleanProperty()),
        ('free', BooleanProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('contents', ListProperty(EmbeddedObjectProperty(type=ThreatSubObject))),
    ])



class Feeds(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'feeds'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('contained', ListProperty(ThreatReference(valid_types='feed', spec_version='2.1'))),
    ])


class Pallet(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'pallet'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('cartons', ListProperty(ThreatReference(valid_types='carton', spec_version='2.1'))),
    ])


class Carton(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'carton'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('cases', ListProperty(ThreatReference(valid_types='cases', spec_version='2.1'))),
    ])


class Cases(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'cases'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('userid', StringProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('case_list', ListProperty(ThreatReference(valid_types='case', spec_version='2.1'))),
    ])


class ObservedSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types='observed-data', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class EnrichmentSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types='enrichment', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class NoteSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types='note', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class TaskSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types='task', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class OpinionSubObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types='opinion', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class Case(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'case'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('status', StringProperty()),
        ('case_type', StringProperty()),
        ('case_priority', StringProperty()),
        ('case_source', StringProperty()),
        ('assigned', ListProperty(ReferenceProperty(valid_types='identity', spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('observed', ListProperty(EmbeddedObjectProperty(type=ObservedSubObject))),
        ('enrichments', ListProperty(EmbeddedObjectProperty(type=EnrichmentSubObject))),
        ('notes', ListProperty(EmbeddedObjectProperty(type=NoteSubObject))),
        ('tasks', ListProperty(EmbeddedObjectProperty(type=TaskSubObject))),
        ('opinions', ListProperty(EmbeddedObjectProperty(type=OpinionSubObject))),
    ])


class Enrichment(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'enrichment'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('paid', BooleanProperty()),
        ('free', BooleanProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'))),
    ])


class Task(_DomainObject):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'task'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('authors', ListProperty(StringProperty)),
        ('assigned', ListProperty(ReferenceProperty(valid_types='identity', spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'))),
    ])

