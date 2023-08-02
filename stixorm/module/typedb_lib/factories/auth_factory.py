import functools
import hashlib

from stixorm.module.authorise import authorised_mappings
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType


class AuthFactory:

    def __init__(self):
        self.auths_by_import_type = {}


    def get_auth_for_import(self,
                            import_type: ImportType):
        json_string = import_type.json()
        hashed_string = hashlib.sha256(json_string.encode()).hexdigest()
        if hashed_string in self.auths_by_import_type.keys():
            return self.auths_by_import_type[hashed_string]
        else:
            authorised_mapping = authorised_mappings(import_type)
            self.auths_by_import_type[hashed_string] = authorised_mapping
            return authorised_mapping

@functools.lru_cache(maxsize=None)
def get_auth_factory_instance() -> AuthFactory:
    return AuthFactory()