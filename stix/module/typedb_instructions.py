from enum import Enum
from typing import Optional, List

from pydantic import BaseModel
from returns.pipeline import is_successful
from returns.result import safe

from stix.module.type_db_logging import log_insert_query

class ResultStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"
    ALREADY_IN_DB = "already_in_db"
    UNKNOWN = "unknown"

class Result(BaseModel):
    id: str
    status: ResultStatus
    error: Optional[str]


class Instructions:

    def __init__(self):
        self.instructions = []

    def convert_to_result(self):
        results = []
        error = None
        status = ResultStatus.UNKNOWN
        for instruction in self.instructions:
            if instruction.status == AddStatus.SUCCESS:
                status = ResultStatus.SUCCESS
            elif instruction.status == AddStatus.EXCLUDE_EXISTS_IN_DATABASE:
                status = ResultStatus.ALREADY_IN_DB
            elif instruction.status == AddStatus.ERROR:
                status = ResultStatus.ERROR

            results.append(Result(id=instruction.id, error=error, status=status))
        return results

    def cyclical_ids(self):
        cyclical = []
        for instruction in self.instructions:
            if instruction.status == AddStatus.FAILED_CYCLICAL:
                cyclical.append(instruction.id)
        return cyclical

    def update_ids_in_database(self,
                               ids: List[str]):
        for instruction in self.instructions:
            if instruction.id in ids:
                instruction.status = AddStatus.EXCLUDE_EXISTS_IN_DATABASE

    def exist_cyclical_ids(self):
        return len(self.cyclical_ids()) > 0

    def missing_dependency_ids(self):
        missing = []
        for instruction in self.instructions:
            if instruction.status == AddStatus.FAILED_MISSING_DEPENDENCY:
                missing.append(instruction.id)
        return missing

    def exist_missing_dependencies(self):
        return len(self.missing_dependency_ids()) > 0

    @safe
    def create_insert_queries(self,
                              build_insert_query):
        for instruction in self.instructions:
            if instruction.status != AddStatus.STEP_1_ADDED_ID_FOR_INSERTION:
                continue
            result = build_insert_query(instruction.layer)
            is_non_empty_insertion = is_successful(result) and result.unwrap() is not None
            if is_non_empty_insertion:
                instruction.status = AddStatus.STEP_2_CREATED_QUERY
                instruction.insertion_query = result.unwrap()
            elif not is_successful(result):
                instruction.status = AddStatus.ERROR
                instruction.error = str(result.failure())
                log_insert_query(result, instruction.layer)


    def getids(self):
        return range(len(self.instructions))

    def update_instruction_as_success(self,
                                      id: int):
        self.instructions[id].status = AddStatus.SUCCESS

    def update_instruction_as_error(self,
                                    id: int,
                                    error: str):
        self.instructions[id].status = AddStatus.ERROR
        self.instructions[id].error = error

    def get_query_for_id(self,
                         id: int):
        return self.instructions[id].insertion_query

    def insert_add_instruction(self,
                               id: str,
                               layer: dict):
        self.instructions.append(AddInstruction(status=AddStatus.STEP_1_ADDED_ID_FOR_INSERTION, id=id, layer=layer))


    def insert_add_instruction_error(self,
                                     id: str,
                                     error:str):
        self.instructions.append(AddInstruction(status=AddStatus.ERROR, id=id, error=error))

    def insert_add_insert_missing_dependency(self,
                                             id: str):
        self.instructions.append(AddInstruction(status=AddStatus.FAILED_MISSING_DEPENDENCY, id=id))

    def insert_add_instruction_cyclical(self,
                                        id: str,
                                        layer: dict):
        self.instructions.append(AddInstruction(status=AddStatus.FAILED_CYCLICAL, id=id, layer=layer))


class AddStatus(Enum):
    SUCCESS = 'success'
    STEP_1_ADDED_ID_FOR_INSERTION= 'added_id_for_insertion'
    STEP_2_CREATED_QUERY = 'created_query'
    EXCLUDE_EXISTS_IN_DATABASE = 'exists_in_database'
    FAILED_MISSING_DEPENDENCY = 'missing_dependency'
    FAILED_CYCLICAL = 'cyclical'
    ERROR = 'error'


class AddInfo(BaseModel):
    status: AddStatus
    id: str
    error: Optional[str]

class AddInstruction(BaseModel):
    status: AddStatus
    id: str
    layer: Optional[dict]
    insertion_query: Optional[str]
    error: Optional[str]

class AddInstructions(BaseModel):
    order_instructions: List[AddInstruction]
    cyclical: List[AddInstruction]
    errors: List[AddInstruction]
    missing: List[str]