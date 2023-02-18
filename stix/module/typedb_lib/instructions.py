import logging
import traceback
from enum import Enum
from typing import Optional, List, Dict

from networkx import DiGraph
from pydantic import BaseModel
from returns.pipeline import is_successful
from returns.result import safe


from stix.module.typedb_lib.logging import log_insert_query

class TypeQLObject(BaseModel):
    dep_match: str
    dep_insert: str
    indep_ql: str
    core_ql: str
    dep_list: List[str]


class ResultStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"
    ALREADY_IN_DB = "already_in_db"
    UNKNOWN = "unknown"
    CYCLICAL_DEPENDENCY = "cyclical_dependency"
    MISSING_DEPENDENCY = "missing_Dependency"
    VALID_FOR_DB_COMMIT = "valid_for_db_commit"

class Result(BaseModel):
    id: str
    status: ResultStatus
    error: Optional[str]


class Instructions:

    def __init__(self):
        self.instructions: Dict[str, Instruction] = {}
        self.dependencies: DiGraph = None
        self.verified_missing_dependencies = []
        self.order = []


    def convert_to_result(self):
        results = []
        error = None
        status = ResultStatus.UNKNOWN
        for instruction in self.instructions.values():
            if instruction.status in [DeleteStatus.SUCCESS, AddStatus.SUCCESS]:
                status = ResultStatus.SUCCESS
            elif instruction.status == AddStatus.EXCLUDE_EXISTS_IN_DATABASE:
                status = ResultStatus.ALREADY_IN_DB
            elif instruction.status in [DeleteStatus.ERROR, AddStatus.ERROR]:
                status = ResultStatus.ERROR
                error = instruction.error
            elif instruction.status == AddStatus.FAILED_CYCLICAL:
                status = ResultStatus.CYCLICAL_DEPENDENCY
            elif instruction.status == AddStatus.FAILED_MISSING_DEPENDENCY:
                status = ResultStatus.MISSING_DEPENDENCY
            elif instruction.status in [DeleteStatus.STEP_1_CREATED_QUERY, AddStatus.STEP_2_CREATED_QUERY]:
                status = ResultStatus.VALID_FOR_DB_COMMIT

            results.append(Result(id=instruction.id, error=error, status=status))
        return results

    def add_dependencies(self, dependencies: DiGraph):
        self.dependencies = dependencies

    def not_allow_insertion(self,
                            id: str):
        return self.instructions[id].status != AddStatus.STEP_2_CREATED_QUERY

    def cyclical_ids(self):
        cyclical = []
        for instruction in self.instructions.values():
            if instruction.status == AddStatus.FAILED_CYCLICAL:
                cyclical.append(instruction.id)
        return cyclical

    def update_ids_in_database(self,
                               ids: List[str]):
        for instruction in self.instructions.values():
            if instruction.id in ids:
                instruction.status = AddStatus.EXCLUDE_EXISTS_IN_DATABASE

    def exist_cyclical_ids(self):
        return len(self.cyclical_ids()) > 0

    def add_insertion_order(self,
                            order):
        included_ids_in_order = self.instructions.keys()
        # only order for
        for id in order:
            if id in included_ids_in_order:
                self.order.append(id)


    def missing_dependency_ids(self):
        missing = []

        ids_in_instructions = []
        for instruction in self.instructions.values():
            ids_in_instructions.append(instruction.id)

        for node in self.dependencies.nodes:
            if node not in ids_in_instructions:
                missing.append(node)

        return missing

    def exist_missing_dependencies(self):
        return len(self.missing_dependency_ids()) > 0

    def register_missing_dependencies(self,
                                      missing: List[str]):
        self.verified_missing_dependencies = missing
        instruction: AddInstruction
        for instruction in self.instructions.values():
            if len(set(instruction.typeql_obj.dep_list).intersection(set(missing))) > 0:
                instruction.status = AddStatus.FAILED_MISSING_DEPENDENCY


    @safe
    def create_insert_queries(self,
                              build_insert_query):
        for instruction in self.instructions.values():
            if instruction.status != AddStatus.STEP_1_ADDED_ID_FOR_INSERTION:
                continue
            result = build_insert_query(instruction.typeql_obj.dict())
            is_non_empty_insertion = is_successful(result) and result.unwrap() is not None
            if is_non_empty_insertion:
                instruction.status = AddStatus.STEP_2_CREATED_QUERY
                instruction.query = result.unwrap()
            elif not is_successful(result):
                instruction.status = AddStatus.ERROR
                instruction.error = str(result.failure())
                log_insert_query(result, instruction.layer)


    def getids(self):
        return range(len(self.instructions))

    def update_instruction_as_success(self,
                                      id: str):
        self.instructions[id].status = AddStatus.SUCCESS

    def update_delete_instruction_as_success(self,
                                      id: str):
        self.instructions[id].status = DeleteStatus.SUCCESS

    def update_instruction_as_error(self,
                                    id: str,
                                    error: str):
        self.instructions[id].status = AddStatus.ERROR
        self.instructions[id].error = error

    def update_delete_instruction_as_error(self,
                                    id: str,
                                    error: str):
        self.instructions[id].status = DeleteStatus.ERROR
        self.instructions[id].error = error

    def get_query_for_id(self,
                         id: str):
        return self.instructions[id].query

    def insert_add_instruction(self,
                               id: str,
                               typeql_obj: TypeQLObject):
        self.instructions[id] = AddInstruction(status=AddStatus.STEP_1_ADDED_ID_FOR_INSERTION, id=id, typeql_obj=typeql_obj)

    def insert_delete_instruction(self,
                               id: str,
                               layer: dict):
        self.instructions[id] = DeleteInstruction(status=DeleteStatus.STEP_1_CREATED_QUERY,
                                                id=id,
                                                layer=layer,
                                                query=layer['delete'])

    def insert_delete_instruction_error(self,
                                 id: str,
                                 error: Exception):
        if error is None:
            return
        logging.exception("\n".join(traceback.format_exception(error)))
        self.instructions[id] = AddInstruction(status=DeleteStatus.ERROR, id=id, error=error)

    def insert_instruction_error(self,
                                 id: str,
                                 error: Exception):
        if error is None:
            return
        logging.exception("\n".join(traceback.format_exception(error)))
        self.instructions[id] = AddInstruction(status=AddStatus.ERROR, id=id, error=str(error))

    def insert_add_insert_missing_dependency(self,
                                             id: str,
                                             typeql_obj: TypeQLObject):
        self.instructions[id] = AddInstruction(status=AddStatus.FAILED_MISSING_DEPENDENCY, id=id, typeql_obj= typeql_obj)

    def insert_add_instruction_cyclical(self,
                                        id: str,
                                        layer: dict):
        self.instructions[id] = AddInstruction(status=AddStatus.FAILED_CYCLICAL, id=id, layer=layer)


class AddStatus(Enum):
    SUCCESS = 'success'
    STEP_1_ADDED_ID_FOR_INSERTION= 'added_id_for_insertion'
    STEP_2_CREATED_QUERY = 'created_query'
    EXCLUDE_EXISTS_IN_DATABASE = 'exists_in_database'
    FAILED_MISSING_DEPENDENCY = 'missing_dependency'
    FAILED_CYCLICAL = 'cyclical'
    ERROR = 'error'

class DeleteStatus(Enum):
    SUCCESS = "success"
    STEP_1_CREATED_QUERY = 'created_query'
    ERROR= 'error'


class AddInfo(BaseModel):
    status: AddStatus
    id: str
    error: Optional[str]

class Instruction(BaseModel):
    status: AddStatus
    id: str
    layer: Optional[dict]
    query: Optional[str]
    error: Optional[str]

class AddInstruction(Instruction):
    typeql_obj: TypeQLObject

class DeleteInstruction(Instruction):
    pass

class AddInstructions(BaseModel):
    order_instructions: List[AddInstruction]
    cyclical: List[AddInstruction]
    errors: List[AddInstruction]
    missing: List[str]