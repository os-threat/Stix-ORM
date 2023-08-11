from enum import Enum
from typing import List

from pydantic import BaseModel

class AttackVersions(Enum):
    V12_1 = "12.1"

class AttackDomains(Enum):
    ENTERPRISE_ATTACK = "enterprise-attack"
    MOBILE_ATTACK = "mobile-attack"
    ICS_ATTACK = "ics-attack"

class ImportType(BaseModel):
    STIX21: bool
    CVE: bool
    identity: bool
    location: bool
    os_threat: bool
    kestrel: bool
    rules: bool
    ATTACK: bool
    ATTACK_Versions: List[AttackVersions]
    ATTACK_Domains: List[AttackDomains]
    CACAO: bool
    US_DoD: bool



class ImportTypeFactory:

    @staticmethod
    def get_import_type_factory():
        return ImportTypeFactory()

    @staticmethod
    def create_import(stix_21=False,
                      attack=False,
                      cve=False,
                      identity=False,
                      location=False,
                      os_threat=False,
                      kestrel=False,
                      rules=False,
                      us_dod=False,
                      attack_versions=[],
                      attack_domains=[],
                      cacao=False):
        if os_threat and (not stix_21 or not attack):
            raise ValueError("os_threat requires stix_21 and attack")

        return ImportType(
            STIX21=stix_21,
            CVE=cve,
            identity=identity,
            location=location,
            os_threat=os_threat,
            kestrel=kestrel,
            rules=rules,
            ATTACK=attack,
            ATTACK_Versions=attack_versions,
            ATTACK_Domains=attack_domains,
            CACAO=cacao,
            US_DoD=us_dod,
        )

    @staticmethod
    def get_attack_import():
        return ImportType(
            STIX21=True,
            CVE=False,
            identity=False,
            location=False,
            os_threat=False,
            kestrel=False,
            rules=False,
            ATTACK=True,
            ATTACK_Versions=[AttackVersions.V12_1],
            ATTACK_Domains=[AttackDomains.ENTERPRISE_ATTACK, AttackDomains.ICS_ATTACK, AttackDomains.MOBILE_ATTACK],
            CACAO=False,
            US_DoD=False
        )

    @staticmethod
    def get_all_imports():
        return ImportType(
            STIX21=True,
            CVE=True,
            identity=True,
            location=True,
            os_threat=True,
            kestrel=True,
            rules=True,
            ATTACK=True,
            ATTACK_Versions=[AttackVersions.V12_1],
            ATTACK_Domains=[AttackDomains.ENTERPRISE_ATTACK, AttackDomains.ICS_ATTACK, AttackDomains.MOBILE_ATTACK],
            CACAO=True,
            US_DoD=True
        )

    @staticmethod
    def get_default_import():
        return ImportType(
            STIX21 = True,
            CVE = False,
            identity = False,
            location = False,
            os_threat = False,
            kestrel = False,
            rules = False,
            ATTACK = False,
            ATTACK_Versions = [AttackVersions.V12_1],
            ATTACK_Domains = [AttackDomains.ENTERPRISE_ATTACK, AttackDomains.ICS_ATTACK, AttackDomains.MOBILE_ATTACK],
            CACAO= False,
            US_DoD= False
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
            "ATT&CK": import_type.ATTACK,
            "os-threat": import_type.os_threat,
            "kestrel": import_type.kestrel,
            "CACAO": import_type.CACAO,
            "US_DoD": import_type.US_DoD,
            "CVE": import_type.CVE,
            "identity": import_type.identity,
            "location": import_type.location,
            "rules": import_type.rules,
            "ATT&CK_Versions": versions,
            "ATT&CK_Domains": domains
        }


