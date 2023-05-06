
from stixorm.module.authorise import authorised_mappings

import_type = {
    "STIX21": True,
    "os-intel": False,
    "os-hunt": False,
    "CVE": False,
    "identity": False,
    "location": False,
    "rules": False,
    "ATT&CK": False,
    "ATT&CK_Versions": ["12.0"],
    "ATT&CK_Domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    "CACAO": False
}

auth = authorised_mappings(import_type)

print("=========================== names =========================================")
print(f'embedded --> {auth["reln_name"]["embedded_relations"]}\n')
print(f'standard --> {auth["reln_name"]["standard_relations"]}\n')
print(f'list of objects --> {auth["reln_name"]["list_of_objects"]}\n')
print(f'key-vale --> {auth["reln_name"]["key_value_relations"]}\n')
print(f'extensions --> {auth["reln_name"]["extension_relations"]}\n')
print("=========================== dicts =========================================")
print(f'embedded --> {auth["reln"]["embedded_relations"]}\n')
print(f'standard --> {auth["reln"]["standard_relations"]}\n')
print(f'list of objects --> {auth["reln"]["list_of_objects"]}\n')
print(f'key-vale --> {auth["reln"]["key_value_relations"]}\n')
print(f'extensions --> {auth["reln"]["extension_relations"]}\n')
print("=========================== dicts =========================================")
print("=========================== types =========================================")
print(f'sdo --> {auth["tql_types"]["sdo"]}\n')
print(f'sco --> {auth["tql_types"]["sco"]}\n')
print(f'sro --> {auth["tql_types"]["sro"]}\n')
print(f'kmeta--> {auth["tql_types"]["meta"]}\n')
print("=========================== islists =========================================")
print(f'is_lists sdo --> {auth["is_lists"]["sdo"]}\n')
print(f'is_lists sco --> {auth["is_lists"]["sco"]}\n')
print(f'is_lists sro --> {auth["is_lists"]["sro"]}\n')
print(f'is_lists sub-object--> {auth["is_lists"]["sub"]}\n')