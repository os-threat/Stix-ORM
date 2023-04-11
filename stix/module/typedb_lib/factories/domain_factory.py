
from stix.module.definitions.stix21 import stix_models
from stix.module.definitions.attack import attack_models
from stix.module.definitions.os_threat import os_threat_models
from stix.module.definitions.cacao import cacao_models
from stix.module.definitions.kestrel import kestrel_models
from stix.module.typedb_lib.factories.import_type_factory import ImportType


class DomainFactory:

    def __init__(self):
        self.domains = {}
        self.domains["stix"] = stix_models
        self.domains["attack"] = attack_models
        self.domains["os-threat"] = os_threat_models
        self.domains["cacao"] = cacao_models
        self.domains["kestrel"] = kestrel_models

    def get_all_domains(self):
        return self.domains

    def get_domains_for_import(self,
                               import_type: ImportType):
        # setup Stix by default
        auth_domains = [self.domains["stix"]]
        # setup "ATT&CK" if selected
        if import_type.ATTACK:
            auth_domains.append(self.domains["attack"])
        # setup "os-threat" if selected
        if import_type.os_intel or import_type.os_hunt:
            auth_domains.append(self.domains["os-threat"])
        # setup "CACAO" if selected
        if import_type.CACAO:
            auth_domains.append(self.domains["cacao"])
        # setup "kestrel" if selected
        if import_type.kestrel:
            auth_domains.append(self.domains["kestrel"])
        return auth_domains

    @staticmethod
    def get_domain_factory():
        return DomainFactory()

