import functools
import importlib.util
import json
import logging
import os
import pathlib
import pkgutil
from typing import List, Dict
from stixorm.module import definitions
from stixorm.module.typedb_lib.factories.import_type_factory import ImportType
from stixorm.module.typedb_lib.factories.mappings_factory import get_mapping_factory_instance
from stixorm.module.typedb_lib.model.definitions import ModelDefinition, DefinitionName, ModelClassDefinition, \
    ImportTypeToDefinitionMapper


class DomainDefinition:

    def __init__(self,
                 domain_name: str,
                 path,
                 model_class: ModelClassDefinition):
        self.domain_name = domain_name
        self.definition_path = path

        base = self.__get_base()
        mappings = self.__get_mappings()
        sub_objects = self.__get_sub_objects()
        data = self.__get_data()
        # schema = self.__get_schema()
        # rules = self.__getrules()
        # vocab = self.__getvocab()
        # enums = self.__getenums()


        self.__model_definition = ModelDefinition(base=base,
                                                  mappings=mappings,
                                                  sub_objects=sub_objects,
                                                  data=data,
                                                  class_def=model_class)

    def is_json_file(self, filepath):
        _, file_extension = os.path.splitext(filepath)
        return file_extension.lower() == ".json"

    def __load_definition(self,
                          directory_path: str) -> dict:
        if not os.path.isdir(directory_path):
            return {}

        definitions = {}

        # Iterate over every file in the directory
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            if os.path.isfile(filepath) and self.is_json_file(filepath):
                # Do something with the file, for example, print its contents
                file_name, file_ext = os.path.splitext(filename)
                with open(filepath, 'r') as file:
                    definitions[file_name] = json.load(file)
        return definitions
    def __get_data(self) -> dict:
        # Define the directory path
        directory_path = str(self.definition_path.joinpath("data"))

        return self.__load_definition(directory_path)

    def __get_mappings(self) -> dict:

        # Define the directory path
        mappings_factory = get_mapping_factory_instance()

        return mappings_factory.get_mappings_from_definition(self.domain_name)

    def __get_sub_objects(self) -> dict:

        # Define the directory path
        directory_path = str(self.definition_path.joinpath("sub_objects"))

        return self.__load_definition(directory_path)

    def __get_base(self) -> dict:

        # Define the directory path
        directory_path = str(self.definition_path.joinpath("base"))

        return self.__load_definition(directory_path)


    def contains_mapping(self,
                         lookup: str) -> bool:
        return lookup in self.__model_definition.mappings.keys() and len(self.__model_definition.mappings[lookup]) > 0

   #def contains_class(self,
    #                     lookup: str) -> bool:
   #     return lookup in self.__model_definition.c.keys()

    def get_mapping(self,
                    lookup: str,
                    default = None):
        if default is None:
            return self.__model_definition.mappings.get(lookup)
        return self.__model_definition.mappings.get(lookup, default)

    def contains_data(self,
                      lookup: str) -> bool:
        return lookup in self.__model_definition.data.keys() and len(self.__model_definition.data[lookup]) > 0

    def contains_sub_objects(self,
                             lookup) -> bool:
        return lookup in self.__model_definition.sub_objects.keys() and len(self.__model_definition.sub_objects[lookup]) > 0

    def get_sub_objects(self,
                 lookup: str):
        return self.__model_definition.sub_objects[lookup]

    def get_data(self,
                 lookup: str):
        return self.__model_definition.data[lookup]

    def get_base(self,
                 lookup: str):
        return self.__model_definition.base[lookup]

    def does_property_contain_values(self,
                                   property: str) -> bool:
        model_def = self.__model_definition.dict()
        return property in model_def and len(model_def[property]) > 0

    def get_property_values(self,
                          property: str):
        model_def = self.__model_definition.dict()
        return model_def[property]

    def does_classes_contain_values(self,
                                   property: str) -> bool:
        model_def = self.__model_definition.class_def.dict()
        return property in model_def and len(model_def[property]) > 0

    def get_classes_property_values(self,
                          property: str):
        model_def = self.__model_definition.class_def.dict()
        return model_def[property]

class DefinitionFactory:

    def __init__(self):
        self.definition_dir = pathlib.Path(__file__).parents[2].joinpath('definitions')

        self.definitions: Dict[str, DomainDefinition] = {}

        package_name = definitions
        package = package_name.__name__
        for importer, subpackage_name, is_pkg in pkgutil.walk_packages(package_name.__path__, package + '.'):
            if is_pkg:
                try:
                    subpackage = importer.find_module(subpackage_name).load_module(subpackage_name)
                    name = subpackage.name
                    model_class = ModelClassDefinition(**subpackage.class_model)
                    self.definitions[name] = DomainDefinition(name, self.definition_dir.joinpath(name), model_class)
                except Exception as e:
                    logging.exception(e)


    def lookup_definition(self, domain_name: DefinitionName) -> DomainDefinition:
        if domain_name.value in self.definitions.keys():
            return self.definitions[domain_name.value]
        raise Exception("Definition for " + domain_name.value + " not found")


    def get_definitions_for_import(self,
                                   import_type: ImportType) -> List[DomainDefinition]:
        definitions = []
        for field_name, field_value in import_type.__dict__.items():
            definition_key = ImportTypeToDefinitionMapper().corresponding_definition_name(field_name)
            if field_value and definition_key is not None:
                definitions.append(self.definitions[definition_key.value])
        return definitions



@functools.lru_cache(maxsize=None)
def get_definition_factory_instance() -> DefinitionFactory:
    return DefinitionFactory()