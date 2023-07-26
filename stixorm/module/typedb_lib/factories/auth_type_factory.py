from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.model.definitions import DefinitionName

stix_models = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
attack_models = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK)
os_threat_models = get_definition_factory_instance().lookup_definition(DefinitionName.OS_THREAT)
cacao_models = get_definition_factory_instance().lookup_definition(DefinitionName.CACAO)
kestrel_models = get_definition_factory_instance().lookup_definition(DefinitionName.KESTREL)
us_dod_models = get_definition_factory_instance().lookup_definition(DefinitionName.US_DoD)

class AuthTypeFactory:


    def __init__(self):
        self.auth_types = {}
        self.auth_types["stix"] = stix_models
        self.auth_types["attack"] = attack_models
        self.auth_types["os_threat"] = os_threat_models
        self.auth_types["cacao"] = cacao_models
        self.auth_types["kestrel"] = kestrel_models
        self.auth_types["us_dod"] = us_dod_models


