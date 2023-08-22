import importlib.util
import json
import os
import pathlib
from typing import Dict, List
import functools

from stixorm.module.typedb_lib.model.definitions import ObjectKeys

@functools.lru_cache(maxsize=None)
def get_mapping_factory_instance():
    return MappingsFactory()

class MappingsDefinition():

    def __init__(self,
                 name,
                 path):
        self.definition_name = name
        self.definition_path = path

        self.mapping = self.__load_mappings()

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

    def __load_mappings(self) -> dict:

        # Define the directory path
        directory_path = str(self.definition_path.joinpath("mappings"))

        return self.__load_definition(directory_path)

    def get_mappings(self) -> dict:
        return self.mapping

    def get_object_conversion(self) -> list:
        return self.mapping.get("object_conversion", [])
class MappingsFactory():

    def __init__(self):
        self.definition_dir = pathlib.Path(__file__).parents[2].joinpath('definitions')

        self.definitions: Dict[str, MappingsDefinition] = {}

        subfolder_names = self.get_subfolder_names(self.definition_dir)

        for name in subfolder_names:
            self.definitions[name] = MappingsDefinition(name, self.definition_dir.joinpath(name))

        self.sub_objects_by_name = {}
        self.all_sub_objects = []
        for name in subfolder_names:
            object_conversion = self.definitions[name].get_object_conversion()
            sub_objects = [x for x in object_conversion if x["object"] == "sub"]
            self.sub_objects_by_name[name] = sub_objects
            self.all_sub_objects.extend(sub_objects)


    def all_object_keys(self) -> set[ObjectKeys]:
        return set(list(ObjectKeys))

    def all_object_keys_as_string(self) -> set[str]:
        return set([key.value for key in self.all_object_keys()])

    def get_all_types(self) -> List[str]:
        types = []
        for mapping in self.definitions.values():
            for object_conversion in mapping.get_object_conversion():
                if "type" in object_conversion and object_conversion["object"] in self.all_object_keys_as_string():
                    types.append(object_conversion["type"])
        return list(set(types))


    def get_subfolder_names(self, folder_path):
        subfolder_names = []
        for item in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item)
            if os.path.isdir(item_path):
                subfolder_names.append(item)
        return subfolder_names

    def get_mapping_definition(self,
                               name):
        if name in self.definitions.keys():
            return self.definitions.get(name)
        raise Exception(f"Mapping definition {name} not found")


    def get_mappings_from_definition(self,
                                     name):
        return self.get_mapping_definition(name).get_mappings()

    def get_all_sub_objects(self):
        return self.all_sub_objects

    def get_ext_class(self, key: str, name: str):
        sub_objects = self.sub_objects_by_name.get(name, [])
        for sub_object in sub_objects:
            if sub_object["type"] == key:
                object_name = sub_object["class"]

                module_path = self.definition_dir.joinpath(name).joinpath("classes.py")
                # Load the module using importlib
                spec = importlib.util.spec_from_file_location("classes", module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return getattr(module, object_name)

        raise Exception (f"Class for {key} not found")