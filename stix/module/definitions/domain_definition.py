import json
import os
import pathlib
from abc import ABC, abstractmethod
from enum import Enum
##############################################
#
# Denis these references below are clumsy, can we build a proper object registry please as a refactor?
# One were i dont have to manually specify the classes manually
#
###############################################

# from stix.module.definitions.os_threat.classes import (
#     ThreatSubObject, StateChangeObject, EventCoreExt, EntityCountObject, ImpactCoreExt, Availability,
#     Confidentiality, External, Integrity, Monetary, Physical, Traceability, IncidentScoreObject,
#     IncidentCoreExt, TaskCoreExt, EvidenceCoreExt
#
# )
#
# os_threat_models = {
#     "ThreatSubObject" : ThreatSubObject,
#     "StateChangeObject": StateChangeObject,
#     "EventCoreExt": EventCoreExt,
#     "EntityCountObject": EntityCountObject,
#     "ImpactCoreExt": ImpactCoreExt,
#     "Availability": Availability,
#     "Confidentiality": Confidentiality,
#     "External": External,
#     "Integrity": Integrity,
#     "Monetary": Monetary,
#     "Physical": Physical,
#     "Traceability": Traceability,
#     "IncidentScoreObject": IncidentScoreObject,
#     "IncidentCoreExt": IncidentCoreExt,
#     "TaskCoreExt": TaskCoreExt,
#     "EvidenceCoreExt": EvidenceCoreExt
# }


class DefinitionNames(str, Enum):
    ATTACK = "attack"
    CACAO = "cacao"
    KESTREL = "kestrel"
    OS_THREAT = "os-threat"
    STIX_21 = "stix"
    US_DoD = "us-dod"


class ObjectKeys(str, Enum):
    SDO = "sdo"
    SRO = "sro"
    SCO = "sco"
    SUB = "sub"
    META = "meta"


class DomainDefinition:

    def __init__(self,
                 domain_name: str,
                 path):
        self.domain_name = domain_name
        self.definition_path = path

    def get_mappings(self) -> dict:

        # Define the directory path
        directory_path = str(self.definition_path.joinpath("mappings"))

        if not os.path.isdir(directory_path):
            return {}

        mappings = {}

        # Iterate over every file in the directory
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            if os.path.isfile(filepath):
                # Do something with the file, for example, print its contents
                file_name, file_ext = os.path.splitext(filename)
                with open(filepath, 'r') as file:
                    mappings[file_name] = json.load(file)
        return mappings

    def get_object_conversion(self) -> list:
        return self.get_mappings().get("object_conversion", [])

    def all_object_keys(self) -> set[ObjectKeys]:
        return set(list(ObjectKeys))

    def all_object_keys_as_string(self) -> set[str]:
        return set([key.value for key in self.all_object_keys()])

    def get_all_types(self) -> set[str]:
        types = []
        for object_conversion in self.get_object_conversion():
            if "type" in object_conversion and object_conversion["object"] in self.all_object_keys_as_string():
                types.append(object_conversion["type"])
        return set(types)



def get_ext_list(mydir):
    local_list = []
    file_path = os.path.join(mydir, "mappings", "object_conversion.json")
    if os.path.isfile(file_path):
        with open(file_path, mode="r", encoding="utf-8") as f:
            json_text = json.load(f)
            local_list = [x for x in json_text if x["object"] == "sub"]

    return local_list


class Definitions:

    def __init__(self):
        definitions_dir = pathlib.Path(__file__).parent.absolute()

        attack_definitions_dir = definitions_dir.joinpath(DefinitionNames.ATTACK.value)
        attack_sub = get_ext_list(attack_definitions_dir)
        attack_definition = DomainDefinition(DefinitionNames.ATTACK.value,
                                             attack_definitions_dir)

        cacao_definitions_dir = definitions_dir.joinpath(DefinitionNames.CACAO.value)
        cacao_sub = get_ext_list(cacao_definitions_dir)
        cacao_definition = DomainDefinition(DefinitionNames.CACAO.value,
                                            cacao_definitions_dir)

        kestrel_definitions_dir = definitions_dir.joinpath(DefinitionNames.KESTREL.value)
        kestrel_sub = get_ext_list(kestrel_definitions_dir)
        kestrel_definition = DomainDefinition(DefinitionNames.KESTREL.value,
                                              kestrel_definitions_dir)

        os_threat_definitions_dir = definitions_dir.joinpath("os_threat")
        os_threat_sub = get_ext_list(os_threat_definitions_dir)
        os_threat_definition = DomainDefinition(DefinitionNames.OS_THREAT.value,
                                                os_threat_definitions_dir)

        stix_21_definitions_dir = definitions_dir.joinpath("stix21")
        stix_21_sub = get_ext_list(stix_21_definitions_dir)
        stix_21_definition = DomainDefinition(DefinitionNames.STIX_21.value,
                                              stix_21_definitions_dir)

        us_dod_definitions_dir = definitions_dir.joinpath("us_dod")
        us_dod_sub = get_ext_list(us_dod_definitions_dir)
        us_dod_definition = DomainDefinition(DefinitionNames.US_DoD.value,
                                              us_dod_definitions_dir)

        self.definitions = {}
        self.definitions[DefinitionNames.ATTACK] = attack_definition
        self.definitions[DefinitionNames.CACAO] = cacao_definition
        self.definitions[DefinitionNames.KESTREL] = kestrel_definition
        self.definitions[DefinitionNames.US_DoD] = us_dod_definition
        self.definitions[DefinitionNames.OS_THREAT] = os_threat_definition
        self.definitions[DefinitionNames.STIX_21] = stix_21_definition
        self.sub_objects = []
        self.sub_objects = attack_sub + cacao_sub + kestrel_sub + os_threat_sub + stix_21_sub + us_dod_sub

    def get_definition(self, domain_name: DefinitionNames) -> DomainDefinition:
        if domain_name not in self.definitions:
            raise ValueError(f"Domain name {domain_name} is not a valid domain name")
        return self.definitions.get(domain_name)

    def get_all_types(self) -> set[str]:
        types = set()
        for definition in self.definitions.values():
            types.update(definition.get_all_types())
        return types


def get_ext_class(key, spec_version):
    defin = Definitions()
    list_of_ext = defin.sub_objects
    for ext in list_of_ext:
        if ext["type"] == key:
            return os_threat_models[ext["class"]]


