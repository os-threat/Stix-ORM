from enum import Enum
from typing import List

from pydantic import BaseModel

class AttackVersions(Enum):
    V17 = "17"

class AttackDomains(Enum):
    ENTERPRISE_ATTACK = "enterprise-attack"
    MOBILE_ATTACK = "mobile-attack"
    ICS_ATTACK = "ics-attack"

class ImportType(BaseModel):
    STIX21: bool
    OS_THREAT: bool
    OCA: bool
    MBC: bool
    ATTACK_FLOW: bool
    ATTACK: bool
    ATTACK_Versions: List[AttackVersions]
    ATTACK_Domains: List[AttackDomains]
    RULES: bool



class ImportTypeFactory:

    @staticmethod
    def get_import_type_factory():
        return ImportTypeFactory()

    @staticmethod
    def create_import(stix_21=True,
                      attack=True,
                      attack_flow=True,
                      oca=True,
                      mbc=True,
                      os_threat=True,
                      attack_versions=[AttackVersions.V17],
                      attack_domains=[AttackDomains.ENTERPRISE_ATTACK],
                      rules=True):
        if os_threat and (not stix_21 or not attack):
            raise ValueError("os_threat requires stix_21 and attack")

        return ImportType(
            STIX21=stix_21,
            OS_THREAT=os_threat,
            OCA=oca,
            MBC=mbc,
            ATTACK_FLOW=attack_flow,
            RULES=rules,
            ATTACK=attack,
            ATTACK_Versions=attack_versions,
            ATTACK_Domains=attack_domains
        )

    @staticmethod
    def get_attack_import():
        return ImportType(
            STIX21=True,
            ATTACK=True,
            ATTACK_FLOW=True,
            OCA=True,
            MBC=True,
            OS_THREAT=True,
            RULES=True,
            ATTACK_Versions=[AttackVersions.V17],
            ATTACK_Domains=[AttackDomains.ENTERPRISE_ATTACK]
        )

    @staticmethod
    def get_all_imports():
        return ImportType(
            STIX21=True,
            ATTACK=True,
            ATTACK_FLOW=True,
            OCA=True,
            MBC=True,
            OS_THREAT=True,
            RULES=True,
            ATTACK_Versions=[AttackVersions.V17],
            ATTACK_Domains=[AttackDomains.ENTERPRISE_ATTACK]
        )

    @staticmethod
    def get_default_import():
        return ImportType(
            STIX21=True,
            ATTACK=True,
            ATTACK_FLOW=True,
            OCA=True,
            MBC=True,
            OS_THREAT=True,
            RULES=True,
            ATTACK_Versions=[AttackVersions.V17],
            ATTACK_Domains=[AttackDomains.ENTERPRISE_ATTACK]
        )

    @staticmethod
    def convert_to_dict(
                        import_type: ImportType):
        versions = []
        for version in import_type.ATTACK_Versions:
            versions.append(version.value)

        domains = []
        for domain in import_type.ATTACK_Domains:
            domains.append(domain.value)


        return {
            "STIX21": import_type.STIX21,
            "ATTACK": import_type.ATTACK,
            "OS_THREAT": import_type.OS_THREAT,
            "OCA": import_type.OCA,
            "MBC": import_type.MBC,
            "ATTACK_FLOW": import_type.ATTACK_FLOW,
            "ATTACK_Versions": import_type.ATTACK_Versions,
            "ATTACK_Domains": import_type.ATTACK_Domains,
            "RULES": import_type.RULES
        }


