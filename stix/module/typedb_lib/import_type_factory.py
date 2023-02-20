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
    os_intel: bool
    os_hunt: bool
    kestrel: bool
    rules: bool
    ATTACK: bool
    ATTACK_Versions: List[AttackVersions]
    ATTACK_Domains: List[AttackDomains]
    CACAO: bool



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
                      os_hunt=False,
                      kestrel=False,
                      os_intel=False,
                      rules=False,
                      attack_versions=[],
                      attack_domains=[],
                      cacao=False):
        return ImportType(
            STIX21=stix_21,
            CVE=cve,
            identity=identity,
            location=location,
            os_hunt=os_hunt,
            kestral=kestrel,
            os_intel=os_intel,
            rules=rules,
            ATTACK=attack,
            ATTACK_Versions=attack_versions,
            ATTACK_Domains=attack_domains,
            CACAO=cacao
        )

    @staticmethod
    def get_default_import():
        return ImportType(
            STIX21 = True,
            CVE = False,
            identity = False,
            location = False,
            os_hunt = False,
            kestrel = False,
            os_intel = False,
            rules = False,
            ATTACK = False,
            ATTACK_Versions = [AttackVersions.V12_1],
            ATTACK_Domains = [AttackDomains.ENTERPRISE_ATTACK, AttackDomains.ICS_ATTACK, AttackDomains.MOBILE_ATTACK],
            CACAO= False
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
            "os-intel": import_type.os_intel,
            "os-hunt": import_type.os_hunt,
            "kestrel": import_type.kestrel,
            "CACAO": import_type.CACAO,
            "CVE": import_type.CVE,
            "identity": import_type.identity,
            "location": import_type.location,
            "rules": import_type.rules,
            "ATT&CK_Versions": versions,
            "ATT&CK_Domains": domains
        }


