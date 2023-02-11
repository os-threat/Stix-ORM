"""Python Mitre ATT&CK Stix Class Definitions """

from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty
)
from stix2.utils import NOW
from stix2.v21.base import _DomainObject, _STIXBase21
from stix2.v21.sdo import AttackPattern, CourseOfAction, IntrusionSet, Malware, Tool, Campaign
from stix2.v21.sro import Relationship
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE,
)

import logging
logger = logging.getLogger(__name__)


class AttackRelation(Relationship):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    _invalid_source_target_types = ['bundle', 'language-content', 'marking-definition', 'relationship', 'sighting']

    def __init__(self):
        super().__init__()
        _type = 'course-of-action'
        _properties = self._properties.update(OrderedDict([
            ('x_mitre_version', StringProperty()),
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty()),
        ]))


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
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_shortname', StringProperty()),
    ])


class Technique(AttackPattern):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """
    def __init__(self, allow_custom, **stix_dict):
        super().__init__()
        print("**************************************************************************")
        print("inside technique or subtechnique classes")
        for k,v in self._properties.items():
            print(k, v)
        print("**************************************************************************")
        _type = 'attack-pattern'

        _properties = self._properties.update(OrderedDict([
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty()),
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
        ]))


class SubTechnique(Technique):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """
    def __init__(self, allow_custom, **stix_dict):
        _type = 'attack-pattern'
        _properties = self._properties


class Mitigation(CourseOfAction):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    def __init__(self, allow_custom, **stix_dict):
        super().__init__()
        _type = 'course-of-action'
        _properties = self._properties.update(OrderedDict([
            ('x_mitre_version', StringProperty()),
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty()),
        ]))


class Group(IntrusionSet):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    def __init__(self):
        super().__init__()
        _type = 'intrusion-set'
        _properties = self._properties.update(OrderedDict([
            ('x_mitre_version', StringProperty()),
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty())
        ]))

    def _check_object_constraints(self):
        super(Group, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))


class SoftwareMalware(Malware):
    """For more detailed information on this object's properties, see
    `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    def __init__(self):
        _type = 'malware'
        _properties = self._properties.update(OrderedDict([
            ('x_mitre_version', StringProperty()),
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty()),
            ('malware_types', ListProperty(OpenVocabProperty(MALWARE_TYPE))),
            ('x_mitre_platforms', ListProperty(StringProperty)),
            ('x_mitre_aliases', ListProperty(StringProperty)),
        ]))

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


class SoftwareTool(Tool):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v>`__.
    """
    def __init__(self):
        _type = 'tool'
        _properties = self._properties.update(OrderedDict([
            ('x_mitre_version', StringProperty()),
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty()),
            ('x_mitre_platforms', ListProperty(StringProperty)),
            ('x_mitre_aliases', ListProperty(StringProperty)),
        ]))


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
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
        ('x_mitre_data_source_ref', StringProperty())
    ])

class AttackCampaign(Campaign):
    """For more detailed information on this object's properties, see
        `the MITRE ATT&CK Stix specifications <https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md>`__.
    """

    def __init__(self):
        _type = 'campaign'
        _properties = self._properties.update(OrderedDict([
            ('x_mitre_version', StringProperty()),
            ('x_mitre_contributors', ListProperty(StringProperty)),
            ('x_mitre_modified_by_ref', StringProperty()),
            ('x_mitre_domains', ListProperty(StringProperty)),
            ('x_mitre_attack_spec_version', StringProperty()),
            ('x_mitre_first_seen_citation', StringProperty()),
            ('x_mitre_aliases', StringProperty()),
        ]))


class ObjectVersion(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h>`__.
    """
    # TODO: Fix ReferenceProperty(required=True) - missing type
    _properties = OrderedDict([
        ('object_ref', ListProperty(ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1'), required=True)),
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
        ('x_mitre_contents', ListProperty(EmbeddedObjectProperty(type=ObjectVersion))),
    ])

