import json
import pathlib
import uuid
from enum import Enum
from typing import Optional
from stix2.properties import Property
from stix2.utils import STIXTypeClass
from stix2.base import _STIXBase
from stix2.exceptions import CustomContentError
DEFAULT_VERSION = '2.1'
ERROR_INVALID_ID = (
    "not a valid STIX identifier, must match <object-type>--<UUID>: {}"
)
from stix.module.definitions.domain_definition import DomainDefinition


class DefinitionNames(str, Enum):
    ATTACK = "attack"
    CACAO = "cacao"
    KESTREL = "kestrel"
    OS_THREAT = "os-threat"
    STIX_21 = "stix"
    US_DoD = "us-dod"


class Definitions:

    def __init__(self):
        definitions_dir = pathlib.Path(__file__).parent.absolute()

        attack_definitions_dir = definitions_dir.joinpath(DefinitionNames.ATTACK.value)
        attack_definition = DomainDefinition(DefinitionNames.ATTACK.value,
                                             attack_definitions_dir)

        cacao_definitions_dir = definitions_dir.joinpath(DefinitionNames.CACAO.value)
        cacao_definition = DomainDefinition(DefinitionNames.CACAO.value,
                                            cacao_definitions_dir)

        kestrel_definitions_dir = definitions_dir.joinpath(DefinitionNames.KESTREL.value)
        kestrel_definition = DomainDefinition(DefinitionNames.KESTREL.value,
                                              kestrel_definitions_dir)

        os_threat_definitions_dir = definitions_dir.joinpath("os_threat")
        os_threat_definition = DomainDefinition(DefinitionNames.OS_THREAT.value,
                                                os_threat_definitions_dir)

        stix_21_definitions_dir = definitions_dir.joinpath("stix21")
        stix_21_definition = DomainDefinition(DefinitionNames.STIX_21.value,
                                              stix_21_definitions_dir)

        us_dod_definitions_dir = definitions_dir.joinpath("us_dod")
        us_dod_definition = DomainDefinition(DefinitionNames.US_DoD.value,
                                              us_dod_definitions_dir)

        self.definitions = {}
        self.definitions[DefinitionNames.ATTACK] = attack_definition
        self.definitions[DefinitionNames.CACAO] = cacao_definition
        self.definitions[DefinitionNames.KESTREL] = kestrel_definition
        self.definitions[DefinitionNames.US_DoD] = us_dod_definition
        self.definitions[DefinitionNames.OS_THREAT] = os_threat_definition
        self.definitions[DefinitionNames.STIX_21] = stix_21_definition

    def get_definition(self, domain_name: DefinitionNames) -> DomainDefinition:
        if domain_name not in self.definitions:
            raise ValueError(f"Domain name {domain_name} is not a valid domain name")
        return self.definitions.get(domain_name)

    def get_all_types(self) -> set[str]:
        types = set()
        for definition in self.definitions.values():
            types.update(definition.get_all_types())
        return types


definitions = Definitions()


def get_definitions() -> Definitions:
    return definitions


# TODO: Kestrel was missing from original definition, does this need to be fixed?
def get_libraries():
    return ["stix", "attack", "os-threat", "cacao"]


def get_type_from_id(stix_id):
    return stix_id.split('--', 1)[0]


def _check_uuid(uuid_str, spec_version):
    """
    Check whether the given UUID string is valid with respect to the given STIX
    spec version.  STIX 2.0 requires UUIDv4; 2.1 only requires the RFC 4122
    variant.
    :param uuid_str: A UUID as a string
    :param spec_version: The STIX spec version
    :return: True if the UUID is valid, False if not
    :raises ValueError: If uuid_str is malformed
    """
    uuid_obj = uuid.UUID(uuid_str)

    ok = uuid_obj.variant == uuid.RFC_4122
    if ok and spec_version == "2.0":
        ok = uuid_obj.version == 4

    return ok


def _validate_id(id_, spec_version, required_prefix):
    """
    Check the STIX identifier for correctness, raise an exception if there are
    errors.
    :param id_: The STIX identifier
    :param spec_version: The STIX specification version to use
    :param required_prefix: The required prefix on the identifier, if any.
        This function doesn't add a "--" suffix to the prefix, so callers must
        add it if it is important.  Pass None to skip the prefix check.
    :raises ValueError: If there are any errors with the identifier
    """
    if required_prefix:
        if not id_.startswith(required_prefix):
            raise ValueError("must start with '{}'.".format(required_prefix))

    try:
        if required_prefix:
            uuid_part = id_[len(required_prefix):]
        else:
            idx = id_.index("--")
            uuid_part = id_[idx+2:]

        result = _check_uuid(uuid_part, spec_version)
    except ValueError:
        # replace their ValueError with ours
        raise ValueError(ERROR_INVALID_ID.format(id_))

    if not result:
        raise ValueError(ERROR_INVALID_ID.format(id_))


def is_stix_type(obj_type, spec_version, valid_types):
    if obj_type in valid_types:
        return True
    else:
        return False


class ThreatReference(Property):

    _WHITELIST, _BLACKLIST = range(2)

    def __init__(self, valid_types=None, invalid_types=None, spec_version=DEFAULT_VERSION, **kwargs):
        """
        references sometimes must be to a specific object type
        """
        self.spec_version = spec_version

        if (valid_types is not None and invalid_types is not None) or \
                (valid_types is None and invalid_types is None):
            raise ValueError(
                "Exactly one of 'valid_types' and 'invalid_types' must be "
                "given",
            )

        if valid_types and not isinstance(valid_types, list):
            valid_types = [valid_types]
        elif invalid_types and not isinstance(invalid_types, list):
            invalid_types = [invalid_types]

        if valid_types is not None and len(valid_types) == 0:
            raise ValueError("Impossible type constraint: empty whitelist")

        # Divide type requirements into generic type classes and specific
        # types.  With respect to strings, values recognized as STIXTypeClass
        # enum names are generic; all else are specifics.
        self.valid_types = valid_types
        self.invalid_types = invalid_types

        super(ThreatReference, self).__init__(**kwargs)

    def clean(self, value, allow_custom):
        if isinstance(value, _STIXBase):
            value = value.id
        value = str(value)

        _validate_id(value, self.spec_version, None)

        obj_type = get_type_from_id(value)

        type_ok = is_stix_type(obj_type, self.spec_version, self.valid_types)

        if not type_ok:
            raise ValueError(
                "The type-specifying prefix '%s' for this property is %s"
                % obj_type,
            )

        return value, allow_custom


