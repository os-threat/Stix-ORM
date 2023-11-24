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
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, DictionaryProperty
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
############################################################################

###############################################################################
# Sequence object
#################################################################################

class SequenceExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--be0c7c79-1961-43db-afde-637066a87a64'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Sequence(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'sequence'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('sequenced_object', ThreatReference(valid_types=valid_obj, spec_version='2.1')),
        ('sequence_type', StringProperty()),
        ('step_type', StringProperty()),
        ('on_completion', ThreatReference(valid_types='sequence', spec_version='2.1')),
        ('on_success', ThreatReference(valid_types='sequence', spec_version='2.1')),
        ('on_failure', ThreatReference(valid_types='sequence', spec_version='2.1')),
        ('next_steps', ListProperty(ThreatReference(valid_types='sequence', spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])


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
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', StringProperty()),
        ('event_types', ListProperty(StringProperty)),
        ('goal', StringProperty()),
        ('name', StringProperty()),
        ('sighting_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'))),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', StringProperty()),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])
###############################################################################
# Impact object
#################################################################################


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
        ('impacted_entity_counts', DictionaryProperty(spec_version='2.1')),
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
        ('extension_type', StringProperty(fixed='property-extension')),
        ('investigation_status', StringProperty()),
        ('blocked', BooleanProperty()),
        ('malicious', BooleanProperty()),
        ('criticality', IntegerProperty(min=0)),
        ('determination', StringProperty()),
        ('incident_types', ListProperty(StringProperty)),
        ('impacted_entity_counts', DictionaryProperty(spec_version='2.1')),
        ('recoverability', ListProperty(StringProperty)),
        ('scores', ListProperty(EmbeddedObjectProperty(type=IncidentScoreObject))),
        ('sequence_start_refs', ListProperty(ThreatReference(valid_types='sequence'))),
        ('sequence_refs', ListProperty(ThreatReference(valid_types='sequence'))),
        ('task_refs', ListProperty(ThreatReference(valid_types='task'))),
        ('event_refs', ListProperty(ThreatReference(valid_types='event'))),
        ('impact_refs', ListProperty(ThreatReference(valid_types='impact'))),
        ('other_object_refs', ListProperty(ThreatReference(valid_types=valid_obj))),
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
        ('task_types', ListProperty(StringProperty)),
        ('outcome', StringProperty()),
        ('description', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', StringProperty()),
        ('error', StringProperty()),
        ('impacted_entity_counts', DictionaryProperty(spec_version='2.1')),
        ('name', StringProperty(required=True)),
        ('priority', IntegerProperty(min=0)),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', StringProperty()),
        ('owner', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])


###############################################################################
# Evidence object
#################################################################################

#################################################################################
# Sightings
##################################################################################

class SightingEvidence(_Extension):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--0d76d6d9-16ca-43fd-bd41-4f800ba8fc43'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='property-extension'))
    ])


class SightingAlert(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-alert'
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('log', StringProperty()),
        ('system_id', StringProperty()),
        ('source', StringProperty()),
        ('product', StringProperty()),
        ('format', StringProperty()),
    ])


class SightingAnecdote(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-anecdote'
    _properties = OrderedDict([
        ('person_name', StringProperty()),
        ('person_context', StringProperty()),
        ('report_submission', StringProperty()),
    ])

class SightingContext(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-context'
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('value', StringProperty()),
    ])

class SightingExclusion(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-exclusion'
    _properties = OrderedDict([
        ('source', StringProperty()),
        ('channel', StringProperty()),
    ])


class SightingEnrichment(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-enrichment'
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('url', StringProperty()),
        ('paid', BooleanProperty()),
        ('value', StringProperty()),
    ])


class SightingHunt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-hunt'
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('playbook_id', StringProperty()),
        ('rule', StringProperty()),
    ])

class SightingFramework(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-framework'
    _properties = OrderedDict([
        ('framework', StringProperty()),
        ('version', StringProperty()),
        ('domain', StringProperty()),
        ('comparison', StringProperty()),
        ('comparison_approach', StringProperty()),
    ])


class SightingExternal(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'sighting-external'
    _properties = OrderedDict([
        ('source', StringProperty()),
        ('version', StringProperty()),
        ('last_update', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('pattern', StringProperty()),
        ('pattern_type', StringProperty()),
        ('payload', StringProperty()),
        ('valid_from', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('valid_until', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])

#####################################################################################################
#
# Anecdote SCO
#
######################################################################################################


class AnecdoteExt(_Extension):
    """For more detailed information on this object's properties, see
    `the __.
    """

    _type = 'extension-definition--23676abf-481e-4fee-ac8c-e3d0947287a4'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sco'))
    ])

class Anecdote(_Observable):
    """For more detailed information on this object's properties, see
    `the xxxxxxxxx`__.
    """

    _type = 'anecdote'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('report_date', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('provided_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]


#####################################################################################################
#
# Identity Extension
#
######################################################################################################

class ContactNumber(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'contact-number'
    _properties = OrderedDict([
        ('description', StringProperty()),
        ('contact_number_type', StringProperty(required=True)),
        ('contact_number', StringProperty(required=True)),
    ])


class EmailContact(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'email-contact'
    _properties = OrderedDict([
        ('description', StringProperty()),
        ('digital_contact_type', StringProperty(required=True)),
        ('email_address_ref', ReferenceProperty(valid_types='email-addr', required=True, spec_version='2.1')),
    ])


class SocialMediaContact(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the OS-Threat documentation`__.
    """
    _type = 'social-media-contact'
    _properties = OrderedDict([
        ('description', StringProperty()),
        ('digital_contact_type', StringProperty(required=True)),
        ('user_account_ref', ReferenceProperty(valid_types='user-account', required=True, spec_version='2.1')),
    ])


class IdentityContact(_Extension):
    """For more detailed information on this object's properties, see
    `the
    """

    _type = 'extension-definition--66e2492a-bbd3-4be6-88f5-cc91a017a498'
    _properties = OrderedDict([
        ('extension_type', StringProperty(required=True, fixed='property-extension')),
        ('contact_numbers', ListProperty(EmbeddedObjectProperty(type=ContactNumber))),
        ('email_addresses', ListProperty(EmbeddedObjectProperty(type=EmailContact))),
        ('first_name', StringProperty()),
        ('last_name', StringProperty()),
        ('middle_name', StringProperty()),
        ('prefix', StringProperty()),
        ('social_media_accounts', ListProperty(EmbeddedObjectProperty(type=SocialMediaContact))),
        ('suffix', StringProperty()),
        ('team', StringProperty()),
    ])