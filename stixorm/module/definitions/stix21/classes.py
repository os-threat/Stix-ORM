"""Python Mitre ATT&CK Stix Class Definitions """

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

from stixorm.module.definitions.property_definitions import get_definitions, ThreatReference, ThreatExtensionsProperty
from stixorm.module.typedb_lib.auth_types import all_auth_types

logger = logging.getLogger(__name__)

valid_obj =  list(get_definitions().get_all_types())


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
        ('object_refs', ListProperty(ThreatReference(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])