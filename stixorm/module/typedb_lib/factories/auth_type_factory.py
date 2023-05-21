from stixorm.module.definitions.attack import attack_models
from stixorm.module.definitions.cacao import cacao_models
from stixorm.module.definitions.kestrel import kestrel_models
from stixorm.module.definitions.os_threat import os_threat_models
from stixorm.module.definitions.stix21 import stix_models
from stixorm.module.definitions.us_dod import us_dod_models


class AuthTypeFactory:


    def __init__(self):
        self.auth_types = {}
        self.auth_types["stix"] = stix_models
        self.auth_types["attack"] = attack_models
        self.auth_types["os_threat"] = os_threat_models
        self.auth_types["cacao"] = cacao_models
        self.auth_types["kestrel"] = kestrel_models
        self.auth_types["us_dod"] = us_dod_models


