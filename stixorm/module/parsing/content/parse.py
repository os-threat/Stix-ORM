
from pydantic import BaseModel
from typing import List, Dict, Union, Optional
import logging
import copy


logger = logging.getLogger(__name__)


class ParseContent(BaseModel):
	"""
	ParseContent is a Pydantic model that represents the ORM content used for parsing.
	"""
	stix_type: str
	protocol: str
	group: str
	python_class: str
	typeql: str
	condition1: Optional[str] = None
	field1: Optional[str] = None
	value1: Optional[str] = None
	condition2: Optional[str] = None
	field2: Optional[str] = None
	value2: Optional[str] = None

	def __str__(self):
		return f"ParseContent(stix_type={self.stix_type}, protocol={self.protocol}, group={self.group}, python_class={self.python_class}, typeql={self.typeql}, condition1={self.condition1}, field1={self.field1}, value1={self.value1}, condition2={self.condition2}, field2={self.field2}, value2={self.value2})"
	




# Define the path to the content file
content = "./content/class_registry.json"

###################################################################################
#
# Base - Get Content Record from List Based on Dict Loop
#
###################################################################################

def get_content_list_for_type(type: str, content_type:str) -> List[ParseContent]:
    """
    Open the content file and return the list of ParseContent models.
    """
    local_content = ""
    if content_type == "class":
        local_content = content
    try:
        with open(local_content, 'r') as file:
            list_data = file.read()
            return [ParseContent(**item) for item in list_data if item.get ("stix_type") == type]
    except FileNotFoundError:
        logger.error(f"Content file {local_content} not found.")
        return None
    except Exception as e:
        logger.error(f"Error reading content file: {e}")
        return None

def process_exists_condition(stix_dict, field_list):
    """
    Process the EXISTS condition for the given field list.

    Args:
        stix_dict (Dict[str, str]): The STIX dictionary object.
        field_list (List[str]): The list of fields to check for existence.

    Returns:
        bool: True if all fields exist in the STIX dictionary, False otherwise.
    """
    local_dict = copy.deepcopy(stix_dict)
    correct = False
    length = len(field_list)
    for i, field in enumerate(field_list):
        if length == i+1:
            if field in local_dict:
                correct = True
                return correct
            else:
                correct = False
                return correct
        else:
            if field in local_dict:
                local_dict = local_dict[field]
            else:
                correct = False
                return correct

def process_starts_with_condition(stix_dict, value):
    """
    Process the STARTS_WITH condition for the given field list.

    Args:
        stix_dict (Dict[str, str]): The STIX dictionary to check against.
        field_list (List[str]): The list of fields to check for existence.
        value (str): The value to check for.

    Returns:
        bool: True if it is not an attack object, and any field starts with the given value, False otherwise.
    """
    correct = False
    local_dict = copy.deepcopy(stix_dict)
    if "x_mitre_attack_spec_version" in local_dict:
        return correct
    for field in local_dict.values():
        if isinstance(field, str) and field.startswith(value):
            correct = True
            return correct
    return correct

def process_equals_condition(stix_dict, field_list, value):
    """
    Process the EQUALS condition for the given field and value.

    Args:
        stix_dict (Dict[str, str]): The STIX dictionary to check against.
        field (str): The field to check for equality.
        value (str): The value to check against.

    Returns:
        bool: True if the field exists and it equals the value, False otherwise.
    """
    local_dict = copy.deepcopy(stix_dict)
    correct = False
    length = len(field_list)
    for i, field in enumerate(field_list):
        if length == i+1:
            if field in local_dict:
                if local_dict[field] == value:
                    correct = True
                    return correct
        else:
            if field in local_dict:
                local_dict = local_dict[field]
    return correct

def test_object_by_condition(item: ParseContent, stix_dict: Dict[str, str]) -> bool:
    """
    Test the ParseContent condition against the STIX dictionary .

    Args:
        item (ParseContent): The ParseContent condition to test.
        stix_dict (Dict[str, str]): The STIX dictionary to match against.

    Returns:
        bool: True if the dict matches the conditions, False otherwise.
    """
    correct = False
    # Check each condition in the STIX dictionary
    if item.condition1 == "EXISTS":
        field_list = item.field1.split(".")
        correct = process_exists_condition(stix_dict, field_list)
    elif item.condition1 == "STARTS_WITH":
        correct = process_starts_with_condition(stix_dict, item.value1)
    elif item.condition1 == "EQUALS":
        field_list = item.field1.split(".")
        correct = process_equals_condition(stix_dict, field_list, item.value1)
    # Check the second condition if it exists
    if item.condition2 and correct:
        if item.condition2 == "EQUALS":
            field_list = item.field2.split(".")
            correct = process_equals_condition(stix_dict, field_list, item.value2)
    return correct

def determine_content_object_from_list_by_tests(stix_dict: Dict[str, str], content_type:str) -> ParseContent:
    """
    Determine the content object from the list by matching the STIX dictionary.

    Args:
        stix_dict (Dict[str, str]): The STIX dictionary to match against.
        content_type (str): The type of content to match against "class" or "icon".

    Returns:
        ParseContent: The matching ParseContent object, or None if not found.
    """
    content_list: List[ParseContent] = get_content_list_for_type(stix_dict.get("type"), content_type)
    if not content_list:
        return None
    elif len(content_list) == 1:
        return ParseContent(content_list[0])
    else:
        correct = False
        # Split the list
        default = [item for item in content_list if item.condition1 == ""]
        specialisation = [item for item in content_list if item.condition1 != ""]
        # First check the specialisation list for test matches
        for item in specialisation:
            correct = test_object_by_condition(ParseContent(**item), stix_dict)
            if correct:
                return ParseContent(**item)

        # Else return the default, or worst case the first in the specialisation list
        return ParseContent(**default[0]) if default else ParseContent(**specialisation[0])
    

###################################################################################################
#
# Specific - Get TQL Name from Content by Type and Protocol
#
####################################################################################################

def get_tqlname_from_type_and_protocol(stix_type, protocol) -> Union[str, None]:
    """
    Get the TypeQL name from the type and protocol.

    Args:
        stix_type (str): The type of the object.
        protocol (str): The protocol to use.

    Returns:
        tql_name (str): The TypeQL name of the object.
    """
    content_list: List[ParseContent] = get_content_list_for_type(type, "class")
    if not content_list:
        return None
    elif len(content_list) == 1:
        content = content_list[0]
        return content.typeql
    else:
        for item in content_list:
            if item.protocol == protocol and item.stix_type == stix_type:
                return item.typeql
    return content_list[0].typeql