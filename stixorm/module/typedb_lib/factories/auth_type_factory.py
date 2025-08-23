from stixorm.module.typedb_lib.factories.definition_factory import get_definition_factory_instance
from stixorm.module.typedb_lib.model.definitions import DefinitionName

stix_models = get_definition_factory_instance().lookup_definition(DefinitionName.STIX_21)
attack_models = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK)
os_threat_models = get_definition_factory_instance().lookup_definition(DefinitionName.OS_THREAT)
attack_flow_models = get_definition_factory_instance().lookup_definition(DefinitionName.ATTACK_FLOW)
mbc_models = get_definition_factory_instance().lookup_definition(DefinitionName.MBC)
oca_models = get_definition_factory_instance().lookup_definition(DefinitionName.OCA)

class AuthTypeFactory:


    def __init__(self):
        self.auth_types = {}
        self.auth_types["stix"] = stix_models
        self.auth_types["attack"] = attack_models
        self.auth_types["os_threat"] = os_threat_models
        self.auth_types["attack_flow"] = attack_flow_models
        self.auth_types["mbc"] = mbc_models
        self.auth_types["oca"] = oca_models


