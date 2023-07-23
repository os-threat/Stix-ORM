"""Python CACAO Stix Class Definitions """

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

