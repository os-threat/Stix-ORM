"""Python Mitre ATT&CK Stix Class Definitions """

from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty, OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.utils import NOW
from stix2.v21.base import _DomainObject, _STIXBase21
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE,
)

import logging
logger = logging.getLogger(__name__)


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
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
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
        ('x_mitre_version', StringProperty()),
        ('x_mitre_contributors', ListProperty(StringProperty)),
        ('x_mitre_modified_by_ref', StringProperty()),
        ('x_mitre_domains', ListProperty(StringProperty)),
        ('x_mitre_attack_spec_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
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
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
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
        ('revoked', BooleanProperty(default=lambda: True)),
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
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v>`__.
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


class ObjectVersion(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h>`__.
    """

    _properties = OrderedDict([
        ('object_ref', ReferenceProperty(required=True)),
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
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_contents', ListProperty(ObjectVersion)),
    ])

