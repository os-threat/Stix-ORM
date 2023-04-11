import json
from typing import List

import pathlib
from pydantic import BaseModel


class ProcessMap(BaseModel):
    name: str
    keys: List[str]
    match: List[str]
    cond: List[str]

class ProcessMapFactory:

    def __init__(self):
        self.process_map: List[ProcessMap] = []
        self.__load_data()

    @staticmethod
    def process_map_factory() -> 'ProcessMapFactory':
        return ProcessMapFactory()

    # Load process_map.json
    def __load_data(self):
        path = pathlib.Path(__file__).parent.joinpath("process_map.json")
        with open(str(path), 'r') as file:
            data = json.load(file)
        for process_map in data:
            self.process_map.append(ProcessMap(**process_map))

    def all_process_maps(self) -> List[ProcessMap]:
        return self.process_map
