"""Python Attack-Flow Stix Class Definitions """

from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty, OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.utils import NOW
from stix2.v21 import _Extension
from stix2.v21.base import _DomainObject, _STIXBase21
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE,
)

from stixorm.module.definitions.property_definitions import ThreatReference, ThreatExtensionsProperty


import logging
logger = logging.getLogger(__name__)


##################################################################################
#       SDO
##################################################################################


class AttackFlowExt(_Extension):
    """For more detailed information on this object's properties, see
    `the __.
    """

    _type = 'extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo'))
    ])


class AttackFlow(_DomainObject):
    """For more detailed information on this object's properties, see
    `the Attack Flow specification <https://center-for-threat-informed-defense.github.io/attack-flow/language/#attack-flow-sdos>`__.
    """

    _type = 'attack-flow'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('scope', StringProperty(required=True)),
        ('start_refs', ListProperty(ThreatReference(valid_types=['attack-action', 'attack-condition'], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])




class FlowAction(_DomainObject):
    """For more detailed information on this object's properties, see
    `the Attack Flow specification <https://center-for-threat-informed-defense.github.io/attack-flow/language/#attack-actions>`__.
    """

    _type = 'attack-action'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('tactic_id', StringProperty()),
        ('tactic_ref', ThreatReference(valid_types='x-mitre-tactic', spec_version='2.1')),
        ('technique_id', StringProperty()),
        ('technique_ref', ThreatReference(valid_types='attack-pattern', spec_version='2.1')),
        ('description', StringProperty()),
        ('execution_start', TimestampProperty()),
        ('execution_end', TimestampProperty()),
        ('command_ref', ThreatReference(valid_types='process', spec_version='2.1')),
        ('asset_refs', ListProperty(ThreatReference(valid_types="attack-asset", spec_version='2.1'))),
        ('effect_refs', ListProperty(ThreatReference(valid_types=['attack-action', 'attack-condition',"attack-operator"], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])



class FlowAsset(_DomainObject):
    """For more detailed information on this object's properties, see
    `the Attack Flow specification <https://center-for-threat-informed-defense.github.io/attack-flow/language/#attack-asset>`__.
    """

    _type = 'attack-asset'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('object_ref', ThreatReference(valid_types=['_sdo', '_sco'], spec_version='2.1')),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])






class FlowCondition(_DomainObject):
    """For more detailed information on this object's properties, seehttps://center-for-threat-informed-defense.github.io/attack-flow/language/#attack-condition
    `the Attack Flow specification <https://center-for-threat-informed-defense.github.io/attack-flow/language/#attack-flow-sdos>`__.
    """

    _type = 'attack-condition'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('description', StringProperty(required=True)),
        ('pattern', StringProperty()),
        ('pattern_type', StringProperty()),
        ('pattern_version', StringProperty()),
        ('on_true_refs', ListProperty(ThreatReference(valid_types=['attack-action', 'attack-condition', 'attack-operator'], spec_version='2.1'))),
        ('on_false_refs', ListProperty(ThreatReference(valid_types=['attack-action', 'attack-condition', 'attack-operator'], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])





class FlowOperator(_DomainObject):
    """For more detailed information on this object's properties, see
    `the Attack Flow specification <https://center-for-threat-informed-defense.github.io/attack-flow/language/#attack-operator>`__.
    """

    _type = 'attack-operator'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('operator', StringProperty(required=True)),
        ('effect_refs', ListProperty(ThreatReference(valid_types=['attack-action', 'attack-condition',"attack-operator"], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])

