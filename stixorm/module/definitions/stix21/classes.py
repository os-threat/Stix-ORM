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
    OpenVocabProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, ObservableProperty
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
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, IDENTITY_CLASS, INDUSTRY_SECTOR, REPORT_TYPE
)

import logging

from stixorm.module.definitions.property_definitions import ThreatReference, ThreatExtensionsProperty


logger = logging.getLogger(__name__)

valid_obj =  get_mapping_factory_instance().get_all_types()


class Note(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9>`__.
    """

    _type = 'note'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('abstract', StringProperty()),
        ('content', StringProperty(required=True)),
        ('authors', ListProperty(StringProperty)),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])


class ObservedData(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc>`__.
    """

    _type = 'observed-data'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('first_observed', TimestampProperty(required=True)),
        ('last_observed', TimestampProperty(required=True)),
        ('number_observed', IntegerProperty(min=1, max=999999999, required=True)),
        ('objects', ObservableProperty(spec_version='2.1')),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    def __init__(self, *args, **kwargs):

        if "objects" in kwargs:
            warnings.warn(
                "The 'objects' property of observed-data is deprecated in "
                "STIX 2.1.",
                STIXDeprecationWarning,
            )

        super(ObservedData, self).__init__(*args, **kwargs)

    def _check_object_constraints(self):
        super(ObservedData, self)._check_object_constraints()

        first_observed = self.get('first_observed')
        last_observed = self.get('last_observed')

        if first_observed and last_observed and last_observed < first_observed:
            msg = "{0.id} 'last_observed' must be greater than or equal to 'first_observed'"
            raise ValueError(msg.format(self))

        self._check_mutually_exclusive_properties(
            ["objects", "object_refs"],
        )

class Incident(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_sczfhw64pjxt>`__.
    """

    _type = 'incident'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])


valid_obj =  get_mapping_factory_instance().get_all_types()


class Report(_DomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq>`__.
    """

    _type = 'report'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('report_types', ListProperty(OpenVocabProperty(REPORT_TYPE))),
        ('published', TimestampProperty(required=True)),
        ('object_refs', ListProperty(ThreatReference(valid_types=valid_obj, spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

class Relationship(_RelationshipObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan>`__.
    """

    _invalid_source_target_types = ['bundle', 'language-content', 'marking-definition', 'relationship', 'sighting']

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
        ('source_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1', required=True)),
        ('target_ref', ThreatReference(valid_types=valid_obj, spec_version='2.1', required=True)),
        ('start_time', TimestampProperty()),
        ('stop_time', TimestampProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
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
    #     super(Relationship, self).__init__(**kwargs)

    def _check_object_constraints(self):
        super(self.__class__, self)._check_object_constraints()

        start_time = self.get('start_time')
        stop_time = self.get('stop_time')

        if start_time and stop_time and stop_time <= start_time:
            msg = "{0.id} 'stop_time' must be later than 'start_time'"
            raise ValueError(msg.format(self))

class Sighting(_RelationshipObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a795guqsap3r>`__.
    """

    _type = 'sighting'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('description', StringProperty()),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('count', IntegerProperty(min=0, max=999999999)),
        ('sighting_of_ref', ReferenceProperty(valid_types="SDO", spec_version='2.1', required=True)),
        ('observed_data_refs', ListProperty(ReferenceProperty(valid_types='observed-data', spec_version='2.1'))),
        ('where_sighted_refs', ListProperty(ReferenceProperty(valid_types=['identity', 'location'], spec_version='2.1'))),
        ('summary', BooleanProperty(default=lambda: False)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])

    # Explicitly define the first kwargs to make readable Sighting declarations.
    def __init__(self, sighting_of_ref=None, **kwargs):
        # Allow sighting_of_ref as a positional arg.
        if sighting_of_ref and not kwargs.get('sighting_of_ref'):
            kwargs['sighting_of_ref'] = sighting_of_ref

        super(Sighting, self).__init__(**kwargs)

    def _check_object_constraints(self):
        super(self.__class__, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))

class Identity(_DomainObject):
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
        ('extensions', ThreatExtensionsProperty(spec_version='2.1')),
    ])