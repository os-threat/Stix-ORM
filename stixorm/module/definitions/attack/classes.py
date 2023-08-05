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

from stixorm.module.definitions.property_definitions import ThreatReference
from stixorm.module.typedb_lib.auth_types import all_auth_types
from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance

logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()
# i) allows x- prefix see properties.py line 592 obj_type.startswith("x-") and
# ii) allows non stix definitiosn to be added see properties.py line 592 is_object(obj_type, self.spec_version)

class AttackRelation(_RelationshipObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'relationship'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('relationship_type', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('source_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1', required=True)),
        ('target_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1', required=True)),
        ('start_time', TimestampProperty()),
        ('stop_time', TimestampProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    # Explicitly define the first three kwargs to make readable Relationship declarations.
    # def __init__(
    #     self, source_ref=None, relationship_type=None,
    #     target_ref=None, **kwargs
    # ):
    #     # Allow (source_ref, relationship_type, target_ref) as positional args.
    #     if source_ref and not kwargs.get('source_ref'):
    #         kwargs['source_ref'] = source_ref
    #     if relationship_type and not kwargs.get('relationship_type'):
    #         kwargs['relationship_type'] = relationship_type
    #     if target_ref and not kwargs.get('target_ref'):
    #         kwargs['target_ref'] = target_ref
    #
    #     super(AttackRelation, self).__init__(**kwargs)

    def _check_object_constraints(self):
        super(self.__class__, self)._check_object_constraints()

        start_time = self.get('start_time')
        stop_time = self.get('stop_time')

        if start_time and stop_time and stop_time <= start_time:
            msg = "{0.id} 'stop_time' must be later than 'start_time'"
            raise ValueError(msg.format(self))

class Matrix(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'x-mitre-matrix'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('tactic_refs', ListProperty(StringProperty)),
    ])


class Tactic(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'x-mitre-tactic'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_shortname', StringProperty()),
    ])

class Technique(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'attack-pattern'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('x_mitre_network_requirements', BooleanProperty(default=lambda: False)),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('x_mitre_network_requirements', BooleanProperty(default=lambda: False)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_detection', StringProperty()),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('x_mitre_data_sources', ListProperty(StringProperty)),
        ('x_mitre_is_subtechnique', BooleanProperty(default=lambda: False)),
        ('x_mitre_system_requirements', ListProperty(StringProperty)),
        ('x_mitre_tactic_type', ListProperty(StringProperty)),
        ('x_mitre_permissions_required', ListProperty(StringProperty)),
        ('x_mitre_effective_permissions', ListProperty(StringProperty)),
        ('x_mitre_defense_bypassed', ListProperty(StringProperty)),
        ('x_mitre_remote_support', BooleanProperty(default=lambda: False)),
        ('x_mitre_impact_type', ListProperty(StringProperty)),
    ])


class SubTechnique(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'attack-pattern'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('x_mitre_network_requirements', BooleanProperty(default=lambda: False)),
        ('revoked', BooleanProperty(default=lambda: True)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_detection', StringProperty()),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('x_mitre_data_sources', ListProperty(StringProperty)),
        ('x_mitre_is_subtechnique', BooleanProperty(default=lambda: True)),
        ('x_mitre_system_requirements', ListProperty(StringProperty)),
        ('x_mitre_tactic_type', ListProperty(StringProperty)),
        ('x_mitre_permissions_required', ListProperty(StringProperty)),
        ('x_mitre_effective_permissions', ListProperty(StringProperty)),
        ('x_mitre_defense_bypassed', ListProperty(StringProperty)),
        ('x_mitre_remote_support', BooleanProperty(default=lambda: False)),
        ('x_mitre_impact_type', ListProperty(StringProperty)),
    ])


class Mitigation(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'course-of-action'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

class Group(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'intrusion-set'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('goals', ListProperty(StringProperty)),
        ('resource_level', OpenVocabProperty(ATTACK_RESOURCE_LEVEL)),
        ('primary_motivation', OpenVocabProperty(ATTACK_MOTIVATION)),
        ('secondary_motivations', ListProperty(OpenVocabProperty(ATTACK_MOTIVATION))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    def _check_object_constraints(self):
        super(Group, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))


class SoftwareMalware(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'malware'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('malware_types', ListProperty(OpenVocabProperty(MALWARE_TYPE))),
        ('is_family', BooleanProperty(required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('operating_system_refs', ListProperty(ReferenceProperty(valid_types='software', spec_version='2.1'))),
        ('architecture_execution_envs', ListProperty(OpenVocabProperty(PROCESSOR_ARCHITECTURE))),
        ('implementation_languages', ListProperty(OpenVocabProperty(IMPLEMENTATION_LANGUAGE))),
        ('capabilities', ListProperty(OpenVocabProperty(MALWARE_CAPABILITIES))),
        ('sample_refs', ListProperty(ReferenceProperty(valid_types=['artifact', 'file'], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('x_mitre_aliases', ListProperty(StringProperty)),
    ])

    def _check_object_constraints(self):
        super(SoftwareMalware, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))

        if self.is_family and "name" not in self:
            raise PropertyPresenceError(
                "'name' is a required property for malware families",
                SoftwareMalware,
            )


class SoftwareTool(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'tool'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('tool_types', ListProperty(OpenVocabProperty(TOOL_TYPE))),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('tool_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('x_mitre_aliases', ListProperty(StringProperty)),
    ])



class DataSource(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'x-mitre-data-source'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_platforms', ListProperty(StringProperty)),
        ('x_mitre_collection_layers', ListProperty(StringProperty)),
    ])


class DataComponent(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'x-mitre-data-component'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_data_source_ref', StringProperty())
    ])

class AttackCampaign(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'campaign'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('x_mitre_first_seen_citation', StringProperty()),
        ('x_mitre_last_seen_citation', StringProperty()),
        ('x_mitre_aliases', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('objective', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    def _check_object_constraints(self):
        super(AttackCampaign, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))



class ObjectVersion(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """
    _properties = OrderedDict([
        ('object_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1')),
        ('object_modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ])


class Collection(_DomainObject):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _type = 'x-mitre-collection'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('x_mitre_deprecated', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_contents', ListProperty(EmbeddedObjectProperty(type=ObjectVersion))),
    ])

class AttackMarking(_STIXBase21, _MarkingsMixin):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k5fndj2c7c1k>`__.
    """

    _type = 'marking-definition'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('definition_type', StringProperty()),
        ('name', StringProperty()),
        ('definition', MarkingProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    def __init__(self, **kwargs):
        if {'definition_type', 'definition'}.issubset(kwargs.keys()):
            # Create correct marking type object
            try:
                marking_type = OBJ_MAP_MARKING[kwargs['definition_type']]
            except KeyError:
                raise ValueError("definition_type must be a valid marking type")

            if not isinstance(kwargs['definition'], marking_type): # noqa
                defn = _get_dict(kwargs['definition'])
                kwargs['definition'] = marking_type(**defn)

        super(AttackMarking, self).__init__(**kwargs)

    def _check_object_constraints(self):
        super(AttackMarking, self)._check_object_constraints()

        definition = self.get("definition")
        definition_type = self.get("definition_type")
        extensions = self.get("extensions")

        if not (definition_type and definition) and not extensions:
            raise PropertyPresenceError(
                "MarkingDefinition objects must have the properties "
                "'definition_type' and 'definition' if 'extensions' is not present",
                AttackMarking,
            )

        check_tlp_marking(self, '2.1')

    def serialize(self, pretty=False, include_optional_defaults=False, **kwargs):
        check_tlp_marking(self, '2.1')
        return super(AttackMarking, self).serialize(pretty, include_optional_defaults, **kwargs)


OBJ_MAP_MARKING = {
    'tlp': TLPMarking,
    'statement': StatementMarking,
}

class AttackIdentity(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>`__.
    """

    _type = 'identity'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('roles', ListProperty(StringProperty)),
        ('identity_class', OpenVocabProperty(IDENTITY_CLASS)),
        ('sectors', ListProperty(OpenVocabProperty(INDUSTRY_SECTOR))),
        ('contact_information', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])