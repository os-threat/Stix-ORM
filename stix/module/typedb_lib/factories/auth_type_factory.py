from stix.module.definitions.attack import attack_models
from stix.module.definitions.cacao import cacao_models
from stix.module.definitions.kestrel import kestrel_models
from stix.module.definitions.os_threat import os_threat_models
from stix.module.definitions.stix21 import stix_models


class AuthTypeFactory:


    def __init__(self):
        self.auth_types = {}
        self.auth_types["stix"] = stix_models
        self.auth_types["attack"] = attack_models
        self.auth_types["os_threat"] = os_threat_models
        self.auth_types["cacao"] = cacao_models
        self.auth_types["kestrel"] = kestrel_models

