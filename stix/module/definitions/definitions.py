import json
import pathlib
from enum import Enum
from typing import Optional

from stix.module.definitions.domain_definition import DomainDefinition


class DefinitionNames(str, Enum):
    ATTACK = "attack"
    CACAO = "cacao"
    KESTREL = "kestrel"
    OS_THREAT = "os-threat"
    STIX_21 = "stix"


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

        self.definitions = {}
        self.definitions[DefinitionNames.ATTACK] = attack_definition
        self.definitions[DefinitionNames.CACAO] = cacao_definition
        self.definitions[DefinitionNames.KESTREL] = kestrel_definition
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



