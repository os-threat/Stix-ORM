"""Python Mitre ATT&CK Stix Class Definitions """
from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

"""Python Mitre ATT&CK Stix Class Definitions """
import json
import pathlib
from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, FloatProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty
)
from stix2.utils import NOW, _get_dict
from stix2.markings import _MarkingsMixin
from stix2.markings.utils import check_tlp_marking
from stix2.v21.base import _DomainObject, _STIXBase21, _RelationshipObject, _Extension
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
    MarkingProperty, TLPMarking, StatementMarking,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, IDENTITY_CLASS, INDUSTRY_SECTOR,
)

import logging

from stixorm.module.definitions.property_definitions import ThreatReference, ThreatExtensionsProperty


logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()
# i) allows x- prefix see properties.py line 592 obj_type.startswith("x-") and
# ii) allows non stix definitiosn to be added see properties.py line 592 is_object(obj_type, self.spec_version)

############################################################################################
#
# Feed Definitions
#
############################################################################################
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
        ('paid', BooleanProperty()),
        ('free', BooleanProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('contained', ListProperty(ThreatReference(valid_types='feed', spec_version='2.1'))),
    ])


############################################################################################
#
# Incident Definitions
#
############################################################################################
# Event Object
##################################################################################
class StateChangeObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _properties = OrderedDict([
        ('state_change_type', StringProperty()),
        ('initial_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1')),
        ('result_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1')),
    ])


class EventCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--4ca6de00-5b0d-45ef-a1dc-ea7279ea910e'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Event(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'event'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('status', StringProperty()),
        ('changed_objects', ListProperty(EmbeddedObjectProperty(type=StateChangeObject))),
        ('description', StringProperty()),
        ('detection_methods', ListProperty(StringProperty)),
        ('detection_rule', StringProperty()),
        ('detection_system', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', StringProperty()),
        ('event_seq', IntegerProperty()),
        ('event_types', ListProperty(StringProperty)),
        ('goal', StringProperty()),
        ('name', StringProperty()),
        ('sighting_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'))),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', StringProperty()),
        ('subevents', ListProperty(ThreatReference(valid_types='event', spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])
###############################################################################
# Imapct object
#################################################################################


class EntityCountObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _properties = OrderedDict([
        ('individual', IntegerProperty()),
        ('group', IntegerProperty()),
        ('system', IntegerProperty()),
        ('organization', IntegerProperty()),
        ('class', IntegerProperty()),
        ('unknown', IntegerProperty()),
    ])


class ImpactCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Availability(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'availability'
    _properties = OrderedDict([
        ('availability_impact', IntegerProperty()),
    ])


class Confidentiality(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'confidentiality'
    _properties = OrderedDict([
        ('information_type', StringProperty()),
        ('loss_type', StringProperty()),
        ('record_count', IntegerProperty()),
        ('record_size', IntegerProperty()),
    ])

class External(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'external'
    _properties = OrderedDict([
        ('impact_type', StringProperty()),
    ])


class Integrity(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'integrity'
    _properties = OrderedDict([
        ('alteration', StringProperty()),
        ('information_type', StringProperty()),
        ('record_count', IntegerProperty()),
        ('record_size', IntegerProperty()),
    ])


class Monetary(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'monetary'
    _properties = OrderedDict([
        ('variety', StringProperty()),
        ('conversion_rate', FloatProperty()),
        ('conversion_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('currency', StringProperty()),
        ('currency_actual', StringProperty()),
        ('max_amount', FloatProperty()),
        ('min_amount', FloatProperty()),
    ])


class Physical(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'physical'
    _properties = OrderedDict([
        ('impact_type', StringProperty()),
        ('asset_type', StringProperty()),
    ])



class Traceability(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'traceability'
    _properties = OrderedDict([
        ('traceability_impact', StringProperty()),
    ])


class Impact(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'impact'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('impact_category', StringProperty()),
        ('criticality', IntegerProperty()),
        ('description', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', StringProperty()),
        ('impacted_entity_counts', EmbeddedObjectProperty(type=EntityCountObject)),
        ('impacted_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'))),
        ('recoverability', StringProperty()),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', StringProperty()),
        ('superseded_by_ref', ThreatReference(valid_types='impact', spec_version='2.1')),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])


###############################################################################
# Incident Extension object
#################################################################################

class IncidentScoreObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('value', IntegerProperty()),
        ('description', StringProperty()),
    ])


class IncidentCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--ef765651-680c-498d-9894-99799f2fa126'
    _properties = OrderedDict([
        ('determination', StringProperty()),
        ('extension_type', StringProperty(fixed='property-extension')),
        ('investigation_status', StringProperty()),
        ('criticality', IntegerProperty(min=0)),
        ('blocked', BooleanProperty()),
        ('malicious', BooleanProperty()),
        ('impacted_entity_counts', EmbeddedObjectProperty(type=EntityCountObject)),
        ('recoverability', ListProperty(StringProperty)),
        ('scores', EmbeddedObjectProperty(type=IncidentScoreObject)),
        ('incident_types', ListProperty(StringProperty)),
        ('task_refs', ListProperty(ThreatReference(valid_types='task'))),
        ('event_refs', ListProperty(ThreatReference(valid_types='event'))),
        ('impact_refs', ListProperty(ThreatReference(valid_types='impact'))),
        ('notes_refs', ListProperty(ThreatReference(valid_types='notes'))),
        ('evidence_refs', ListProperty(ThreatReference(valid_types='evidence'))),
    ])

###############################################################################
# Task object
#################################################################################

class TaskCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--2074a052-8be4-4932-849e-f5e7798e0030'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Task(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'task'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('changed_objects', ListProperty(EmbeddedObjectProperty(type=StateChangeObject))),
        ('task_type', StringProperty()),
        ('step_type', StringProperty()),
        ('outcome', StringProperty()),
        ('description', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', StringProperty()),
        ('error', StringProperty()),
        ('impacted_entity_counts', EmbeddedObjectProperty(type=EntityCountObject)),
        ('name', StringProperty(required=True)),
        ('priority', IntegerProperty(min=0)),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', StringProperty()),
        ('owner', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('on_completion', ThreatReference(valid_types='task')),
        ('on_failure', ThreatReference(valid_types='task')),
        ('on_success', ThreatReference(valid_types='task')),
        ('next_steps', ListProperty(ThreatReference(valid_types='task'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])


###############################################################################
# Evidence object
#################################################################################

class EvidenceCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--7ff5b5a5-a342-417e-9c0d-339561d9d78a'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Evidence(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'evidence'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('evidence_type', StringProperty()),
        ('source', StringProperty()),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

