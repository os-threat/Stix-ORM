import json
import os
from abc import ABC, abstractmethod
from enum import Enum


class ObjectKeys(str, Enum):
    SDO = "sdo"
    SRO = "sro"
    SCO = "sco"
    SUB = "sub"
    META = "meta"


class DomainDefinition:

    def __init__(self,
                 domain_name: str,
                 path):
        self.domain_name = domain_name
        self.definition_path = path

    def get_mappings(self) -> dict:

        # Define the directory path
        directory_path = str(self.definition_path.joinpath("mappings"))

        if not os.path.isdir(directory_path):
            return {}

        mappings = {}

        # Iterate over every file in the directory
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            if os.path.isfile(filepath):
                # Do something with the file, for example, print its contents
                file_name, file_ext = os.path.splitext(filename)
                with open(filepath, 'r') as file:
                    mappings[file_name] = json.load(file)
        return mappings

    def get_object_conversion(self) -> list:
        return self.get_mappings().get("object_conversion", [])

    def all_object_keys(self) -> set[ObjectKeys]:
        return set(list(ObjectKeys))

    def all_object_keys_as_string(self) -> set[str]:
        return set([key.value for key in self.all_object_keys()])

    def get_all_types(self) -> set[str]:
        types = []
        for object_conversion in self.get_object_conversion():
            if "type" in object_conversion and object_conversion["object"] in self.all_object_keys_as_string():
                types.append(object_conversion["type"])
        return set(types)