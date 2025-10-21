"""
STIX Bundle and List Cleaning Module

This module provides comprehensive cleaning operations for STIX object collections,
including expansion from external sources, SCO field cleaning, circular reference
resolution, dependency sorting, and detailed reporting.
"""

import json
import os
import shutil
import uuid
from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Union, Optional, Tuple, Set, Any
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict
from typing_extensions import Literal

try:
    from stixorm.module.parsing.content.parse import get_group_from_type
except ImportError:
    # Fallback if import fails
    def get_group_from_type(stix_type: str) -> str:
        """Fallback SCO detection based on common SCO types"""
        sco_types = {
            'artifact', 'autonomous-system', 'directory', 'domain-name', 'email-addr',
            'email-message', 'file', 'ipv4-addr', 'ipv6-addr', 'mac-addr', 'mutex',
            'network-traffic', 'process', 'software', 'url', 'user-account',
            'windows-registry-key', 'x509-certificate'
        }
        return "sco" if stix_type in sco_types else "sdo"


# =============================================================================
# Pydantic Model Definitions
# =============================================================================

class StixObject(BaseModel):
    """Base STIX Object model allowing extra fields"""
    model_config = ConfigDict(extra='allow')
    id: str
    type: str


class StixBundle(BaseModel):
    """STIX Bundle model"""
    type: str = "bundle"
    id: str
    objects: List[StixObject]


class ExpansionSource(BaseModel):
    """Model for expansion source information"""
    source_name: str
    found_list: List[str]


class ExpansionReport(BaseModel):
    """Report for expansion operations"""
    number_of_objects_defined: int
    number_of_objects_referenced: int
    missing_ids_list: List[str]
    sources_of_expansion: List[ExpansionSource]


class CleaningSCOReport(BaseModel):
    """Report for SCO cleaning operations"""
    number_of_scos_cleaned: int
    list_of_stix_ids_where_created_field_was_removed: List[str]
    list_of_stix_ids_where_modified_field_was_removed: List[str]
    list_of_stix_ids_where_other_fields_were_removed: List[Dict[str, List[str]]]  # [{"stix_id": str, "removed_fields": List[str]}]


class DeletedFieldAndValue(BaseModel):
    """Model for tracking deleted field information"""
    field_name: str
    deleted_value: Union[str, List[str], Dict]


class DeletedFieldsForObject(BaseModel):
    """Model for tracking deleted fields for a specific object"""
    stix_id: str
    deleted_fields: List[DeletedFieldAndValue]


class CircularReferenceReport(BaseModel):
    """Report for circular reference resolution"""
    number_of_circular_references_found: int
    list_of_circular_reference_paths: List[List[str]]  # Each inner list represents a circular path
    deleted_fields_and_values: List[DeletedFieldsForObject]


class SortingReport(BaseModel):
    """Report for dependency sorting operations"""
    sorting_successful: bool
    sorted_list_of_stix_ids: List[str]
    diagram_of_sorted_dependencies: str  # String representation of dependency graph
    unresolved_references: List[str]


class SingleFileReport(BaseModel):
    """Report for individual file processing"""
    original_file_name: str
    original_file_path: str
    updated_file_name: str
    updated_file_path: str
    report_file_name: str
    report_file_path: str


class FileReport(BaseModel):
    """Report for directory processing"""
    number_of_files_processed: int
    list_of_processed_changes_per_file: List[SingleFileReport]


class OperationsReport(BaseModel):
    """Comprehensive report for all operations"""
    expansion_report: ExpansionReport
    cleaning_sco_report: CleaningSCOReport
    circular_reference_report: CircularReferenceReport
    sorting_report: SortingReport
    file_report: Optional[FileReport] = None


class CleanStixListSuccessReport(BaseModel):
    """Success report for STIX cleaning operations"""
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[True]
    return_message: str
    detailed_operation_reports: OperationsReport


class CleanStixListFailureReport(BaseModel):
    """Failure report for STIX cleaning operations"""
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[False]
    return_message: str
    detailed_operation_reports: OperationsReport


# =============================================================================
# External Data Sources
# =============================================================================

EXTERNAL_SOURCES = [
    {
        "name": "MITRE ATT&CK Enterprise",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json"
    },
    {
        "name": "MITRE ATT&CK Mobile",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json"
    },
    {
        "name": "MITRE ATT&CK ICS",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json"
    },
    {
        "name": "MITRE Atlas",
        "url": "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/refs/heads/main/dist/stix-atlas.json"
    },
    {
        "name": "Malware MBC",
        "url": "https://raw.githubusercontent.com/MBCProject/mbc-stix2.1/refs/heads/main/mbc/mbc.json"
    }
]


# =============================================================================
# Utility Functions
# =============================================================================

def _extract_references_from_object(obj: Dict[str, Any]) -> Set[str]:
    """Extract all STIX ID references from a STIX object"""
    references = set()
    
    # Common reference fields
    ref_fields = [
        'created_by_ref', 'object_marking_refs', 'where_sighted_refs',
        'observed_data_refs', 'sighting_of_ref', 'attributed_to_refs',
        'targets_refs', 'uses_refs', 'indicates_refs', 'based_on_refs',
        'derived_from_refs', 'duplicate_of_refs', 'related_to_refs'
    ]
    
    for field in ref_fields:
        if field in obj:
            value = obj[field]
            if isinstance(value, str) and value.count('--') == 1:
                references.add(value)
            elif isinstance(value, list):
                for ref in value:
                    if isinstance(ref, str) and ref.count('--') == 1:
                        references.add(ref)
    
    # Handle nested objects (like cyber observable references)
    def _extract_from_nested(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key.endswith('_ref') and isinstance(value, str) and value.count('--') == 1:
                    references.add(value)
                elif key.endswith('_refs') and isinstance(value, list):
                    for ref in value:
                        if isinstance(ref, str) and ref.count('--') == 1:
                            references.add(ref)
                else:
                    _extract_from_nested(value)
        elif isinstance(data, list):
            for item in data:
                _extract_from_nested(item)
    
    _extract_from_nested(obj)
    return references


def _fetch_external_data(url: str, timeout: int = 30) -> Optional[List[Dict[str, Any]]]:
    """Fetch STIX objects from external URL with timeout"""
    try:
        with urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode('utf-8'))
            
        # Handle both bundle format and direct object lists
        if isinstance(data, dict) and 'objects' in data:
            return data['objects']
        elif isinstance(data, list):
            return data
        else:
            return []
            
    except (URLError, json.JSONDecodeError, Exception) as e:
        print(f"Warning: Failed to fetch from {url}: {e}")
        return None


def _detect_circular_references(objects: List[StixObject]) -> List[List[str]]:
    """Detect circular reference paths in STIX objects"""
    circular_paths = []
    
    # Build reference graph
    ref_graph = {}
    obj_dict = {obj.id: obj for obj in objects}
    
    for obj in objects:
        obj_data = obj.model_dump()
        references = _extract_references_from_object(obj_data)
        ref_graph[obj.id] = references
    
    # Check for self-references
    for obj_id, refs in ref_graph.items():
        if obj_id in refs:
            circular_paths.append([obj_id, obj_id])
    
    # Check for bidirectional references
    for obj_id, refs in ref_graph.items():
        for ref_id in refs:
            if ref_id in ref_graph and obj_id in ref_graph[ref_id]:
                # Avoid duplicates by ordering
                if obj_id < ref_id:
                    circular_paths.append([obj_id, ref_id])
    
    return circular_paths


def _topological_sort(objects: List[StixObject]) -> Tuple[List[str], List[str], bool]:
    """
    Perform topological sort using Kahn's algorithm
    Returns: (sorted_ids, unresolved_refs, success)
    """
    # Build dependency graph
    in_degree = defaultdict(int)
    adj_list = defaultdict(list)
    obj_dict = {obj.id: obj for obj in objects}
    all_ids = set(obj_dict.keys())
    
    # Initialize in-degree for all objects
    for obj_id in all_ids:
        in_degree[obj_id] = 0
    
    # Build graph and calculate in-degrees
    for obj in objects:
        obj_data = obj.model_dump()
        references = _extract_references_from_object(obj_data)
        
        for ref_id in references:
            if ref_id in all_ids:  # Only consider internal references
                adj_list[ref_id].append(obj.id)
                in_degree[obj.id] += 1
    
    # Kahn's algorithm
    queue = deque([obj_id for obj_id in all_ids if in_degree[obj_id] == 0])
    sorted_ids = []
    
    while queue:
        current = queue.popleft()
        sorted_ids.append(current)
        
        for neighbor in adj_list[current]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
    
    # Check for cycles
    success = len(sorted_ids) == len(all_ids)
    unresolved_refs = [obj_id for obj_id in all_ids if in_degree[obj_id] > 0]
    
    return sorted_ids, unresolved_refs, success


def _create_dependency_diagram(objects: List[StixObject], sorted_ids: List[str]) -> str:
    """Create a string representation of the dependency graph"""
    lines = ["Dependency Diagram:", "=" * 50]
    
    obj_dict = {obj.id: obj for obj in objects}
    
    for i, obj_id in enumerate(sorted_ids):
        obj = obj_dict[obj_id]
        obj_data = obj.model_dump()
        references = _extract_references_from_object(obj_data)
        
        # Filter for internal references only
        internal_refs = [ref for ref in references if ref in obj_dict]
        
        indent = "  " * min(i // 5, 10)  # Progressive indentation
        if internal_refs:
            lines.append(f"{indent}{obj_id} ({obj.type}) -> {len(internal_refs)} refs")
        else:
            lines.append(f"{indent}{obj_id} ({obj.type}) [leaf]")
    
    return "\n".join(lines)


def _prune_unreferenced_objects(objects: List[StixObject], original_objects: List[StixObject]) -> Tuple[List[StixObject], int]:
    """
    Remove objects that were added during expansion but are not actually referenced
    by the original objects or the essential dependency chain.
    
    Args:
        objects: All objects (original + expanded)
        original_objects: Only the original objects from input
        
    Returns:
        Tuple of (pruned_objects, number_pruned)
    """
    # Start with original objects - these are always kept
    original_ids = {obj.id for obj in original_objects}
    essential_objects = list(original_objects)
    essential_ids = set(original_ids)
    
    # Build object lookup
    obj_dict = {obj.id: obj for obj in objects}
    
    # Find all objects that are referenced by essential objects (breadth-first search)
    queue = list(original_objects)
    while queue:
        current_obj = queue.pop(0)
        obj_data = current_obj.model_dump()
        references = _extract_references_from_object(obj_data)
        
        for ref_id in references:
            if ref_id in obj_dict and ref_id not in essential_ids:
                # This referenced object is essential
                essential_ids.add(ref_id)
                essential_objects.append(obj_dict[ref_id])
                queue.append(obj_dict[ref_id])
    
    # Count how many objects were pruned
    pruned_count = len(objects) - len(essential_objects)
    
    return essential_objects, pruned_count


# =============================================================================
# Core Operations
# =============================================================================

def _operation_1_expansion_round_1(objects: List[StixObject]) -> Tuple[List[StixObject], ExpansionReport]:
    """Operation 1: First round of object expansion"""
    # Extract all references and defined IDs
    all_references = set()
    defined_ids = set()
    
    for obj in objects:
        defined_ids.add(obj.id)
        obj_data = obj.model_dump()
        references = _extract_references_from_object(obj_data)
        all_references.update(references)
    
    # Find missing IDs
    missing_ids = all_references - defined_ids
    expansion_sources = []
    found_objects = []
    
    # Search external sources for missing objects
    for source in EXTERNAL_SOURCES:
        if not missing_ids:
            break
            
        external_objects = _fetch_external_data(source["url"])
        if external_objects:
            source_found = []
            for ext_obj in external_objects:
                if ext_obj.get('id') in missing_ids:
                    found_objects.append(StixObject(**ext_obj))
                    source_found.append(ext_obj['id'])
                    missing_ids.discard(ext_obj['id'])
            
            if source_found:
                expansion_sources.append(ExpansionSource(
                    source_name=source["name"],
                    found_list=source_found
                ))
    
    # Combine original and found objects
    expanded_objects = objects + found_objects
    
    # Create expansion report
    report = ExpansionReport(
        number_of_objects_defined=len(defined_ids),
        number_of_objects_referenced=len(all_references),
        missing_ids_list=list(missing_ids),
        sources_of_expansion=expansion_sources
    )
    
    return expanded_objects, report


def _operation_2_expansion_round_2(objects: List[StixObject], round_1_report: ExpansionReport) -> Tuple[List[StixObject], ExpansionReport]:
    """Operation 2: Second round of object expansion for transitive dependencies"""
    # Get current state
    defined_ids = {obj.id for obj in objects}
    all_references = set()
    
    # Extract references from all current objects (including newly added ones)
    for obj in objects:
        obj_data = obj.model_dump()
        references = _extract_references_from_object(obj_data)
        all_references.update(references)
    
    # Find missing IDs
    missing_ids = all_references - defined_ids
    
    # Convert existing sources from round 1 to proper model format
    expansion_sources_models = []
    for source_data in round_1_report.sources_of_expansion:
        if isinstance(source_data, ExpansionSource):
            expansion_sources_models.append(source_data)
        else:
            # Handle legacy dict format
            expansion_sources_models.append(ExpansionSource(
                source_name=source_data["source_name"],
                found_list=source_data["found_list"]
            ))
    
    found_objects = []
    
    # Search external sources for missing objects
    for source in EXTERNAL_SOURCES:
        if not missing_ids:
            break
            
        external_objects = _fetch_external_data(source["url"])
        if external_objects:
            source_found = []
            for ext_obj in external_objects:
                if ext_obj.get('id') in missing_ids:
                    found_objects.append(StixObject(**ext_obj))
                    source_found.append(ext_obj['id'])
                    missing_ids.discard(ext_obj['id'])
            
            if source_found:
                # Update existing source entry or add new one
                existing_source = next((s for s in expansion_sources_models if s.source_name == source["name"]), None)
                if existing_source:
                    existing_source.found_list.extend(source_found)
                else:
                    expansion_sources_models.append(ExpansionSource(
                        source_name=source["name"],
                        found_list=source_found
                    ))
    
    # Combine objects
    final_objects = objects + found_objects
    
    # Update expansion report
    updated_report = ExpansionReport(
        number_of_objects_defined=len({obj.id for obj in final_objects}),
        number_of_objects_referenced=len(all_references),
        missing_ids_list=list(missing_ids),
        sources_of_expansion=expansion_sources_models
    )
    
    return final_objects, updated_report


def _operation_3_sco_cleaning(objects: List[StixObject], clean_sco_fields: bool) -> Tuple[List[StixObject], CleaningSCOReport]:
    """Operation 3: SCO field cleaning (conditional)"""
    if not clean_sco_fields:
        # Return unchanged with empty report
        return objects, CleaningSCOReport(
            number_of_scos_cleaned=0,
            list_of_stix_ids_where_created_field_was_removed=[],
            list_of_stix_ids_where_modified_field_was_removed=[],
            list_of_stix_ids_where_other_fields_were_removed=[]
        )
    
    cleaned_objects = []
    created_removed = []
    modified_removed = []
    other_removed = []
    scos_cleaned = 0
    
    for obj in objects:
        is_sco = get_group_from_type(obj.type) == "sco"
        
        if is_sco:
            obj_data = obj.model_dump()
            original_obj_data = obj_data.copy()
            fields_to_remove = []
            
            # Remove forbidden fields for SCOs
            if 'created' in obj_data:
                del obj_data['created']
                created_removed.append(obj.id)
                fields_to_remove.append('created')
            
            if 'modified' in obj_data:
                del obj_data['modified']
                modified_removed.append(obj.id)
                fields_to_remove.append('modified')
            
            # Check for other non-standard fields (basic validation)
            standard_fields = {'type', 'id', 'spec_version', 'object_marking_refs', 'granular_markings'}
            # Add type-specific standard fields here if needed
            
            other_fields_removed = []
            for field in list(obj_data.keys()):
                if field not in standard_fields and field not in ['created', 'modified']:
                    # This is a simplified check - in practice you'd want more sophisticated field validation
                    pass  # Keep for now, but this is where you'd remove non-standard fields
            
            if fields_to_remove or other_fields_removed:
                scos_cleaned += 1
                if other_fields_removed:
                    other_removed.append({
                        "stix_id": obj.id,
                        "removed_fields": other_fields_removed
                    })
                
                cleaned_objects.append(StixObject(**obj_data))
            else:
                cleaned_objects.append(obj)
        else:
            cleaned_objects.append(obj)
    
    report = CleaningSCOReport(
        number_of_scos_cleaned=scos_cleaned,
        list_of_stix_ids_where_created_field_was_removed=created_removed,
        list_of_stix_ids_where_modified_field_was_removed=modified_removed,
        list_of_stix_ids_where_other_fields_were_removed=other_removed
    )
    
    return cleaned_objects, report


def _operation_4_circular_reference_resolution(objects: List[StixObject]) -> Tuple[List[StixObject], CircularReferenceReport]:
    """Operation 4: Resolve circular references"""
    circular_paths = _detect_circular_references(objects)
    deleted_fields = []
    resolved_objects = []
    
    # Create a mapping for modifications
    obj_modifications = {obj.id: obj.model_dump() for obj in objects}
    
    for path in circular_paths:
        if len(path) == 2 and path[0] == path[1]:
            # Self-reference case
            obj_id = path[0]
            obj_data = obj_modifications[obj_id]
            deleted_fields_for_obj = []
            
            # Remove self-referencing fields
            ref_fields = ['created_by_ref', 'object_marking_refs']
            for field in ref_fields:
                if field in obj_data:
                    value = obj_data[field]
                    if field == 'created_by_ref' and value == obj_id:
                        deleted_fields_for_obj.append(DeletedFieldAndValue(
                            field_name=field,
                            deleted_value=value
                        ))
                        del obj_data[field]
                    elif field == 'object_marking_refs' and isinstance(value, list) and obj_id in value:
                        new_value = [v for v in value if v != obj_id]
                        deleted_fields_for_obj.append(DeletedFieldAndValue(
                            field_name=field,
                            deleted_value=[obj_id]
                        ))
                        if new_value:
                            obj_data[field] = new_value
                        else:
                            del obj_data[field]
            
            if deleted_fields_for_obj:
                deleted_fields.append(DeletedFieldsForObject(
                    stix_id=obj_id,
                    deleted_fields=deleted_fields_for_obj
                ))
                
        elif len(path) == 2:
            # Bidirectional reference
            obj1_id, obj2_id = path
            obj1_data = obj_modifications[obj1_id]
            obj2_data = obj_modifications[obj2_id]
            
            # Check for Identity <-> Marking Definition pattern
            obj1_type = obj1_data.get('type', '')
            obj2_type = obj2_data.get('type', '')
            
            if obj1_type == 'identity' and obj2_type == 'marking-definition':
                # Remove object_marking_refs from identity
                if 'object_marking_refs' in obj1_data and obj2_id in obj1_data['object_marking_refs']:
                    old_refs = obj1_data['object_marking_refs']
                    new_refs = [ref for ref in old_refs if ref != obj2_id]
                    deleted_fields.append(DeletedFieldsForObject(
                        stix_id=obj1_id,
                        deleted_fields=[DeletedFieldAndValue(
                            field_name='object_marking_refs',
                            deleted_value=[obj2_id]
                        )]
                    ))
                    if new_refs:
                        obj1_data['object_marking_refs'] = new_refs
                    else:
                        del obj1_data['object_marking_refs']
            elif obj2_type == 'identity' and obj1_type == 'marking-definition':
                # Remove object_marking_refs from identity
                if 'object_marking_refs' in obj2_data and obj1_id in obj2_data['object_marking_refs']:
                    old_refs = obj2_data['object_marking_refs']
                    new_refs = [ref for ref in old_refs if ref != obj1_id]
                    deleted_fields.append(DeletedFieldsForObject(
                        stix_id=obj2_id,
                        deleted_fields=[DeletedFieldAndValue(
                            field_name='object_marking_refs',
                            deleted_value=[obj1_id]
                        )]
                    ))
                    if new_refs:
                        obj2_data['object_marking_refs'] = new_refs
                    else:
                        del obj2_data['object_marking_refs']
            else:
                # Generic bidirectional - remove created_by_ref from second object
                if 'created_by_ref' in obj2_data and obj2_data['created_by_ref'] == obj1_id:
                    deleted_fields.append(DeletedFieldsForObject(
                        stix_id=obj2_id,
                        deleted_fields=[DeletedFieldAndValue(
                            field_name='created_by_ref',
                            deleted_value=obj1_id
                        )]
                    ))
                    del obj2_data['created_by_ref']
    
    # Create resolved objects
    for obj in objects:
        if obj.id in obj_modifications:
            resolved_objects.append(StixObject(**obj_modifications[obj.id]))
        else:
            resolved_objects.append(obj)
    
    report = CircularReferenceReport(
        number_of_circular_references_found=len(circular_paths),
        list_of_circular_reference_paths=circular_paths,
        deleted_fields_and_values=deleted_fields
    )
    
    return resolved_objects, report


def _operation_5_dependency_sorting(objects: List[StixObject]) -> Tuple[List[StixObject], SortingReport]:
    """Operation 5: Sort objects by dependency order"""
    sorted_ids, unresolved_refs, success = _topological_sort(objects)
    
    if success:
        # Reorder objects according to sorted IDs
        obj_dict = {obj.id: obj for obj in objects}
        sorted_objects = [obj_dict[obj_id] for obj_id in sorted_ids]
        diagram = _create_dependency_diagram(sorted_objects, sorted_ids)
    else:
        # If sorting failed, keep original order but report issues
        sorted_objects = objects
        sorted_ids = [obj.id for obj in objects]
        diagram = "Sorting failed due to circular dependencies"
    
    report = SortingReport(
        sorting_successful=success,
        sorted_list_of_stix_ids=sorted_ids,
        diagram_of_sorted_dependencies=diagram,
        unresolved_references=unresolved_refs
    )
    
    return sorted_objects, report


def _operation_6_comprehensive_reporting(
    expansion_report: ExpansionReport,
    sco_report: CleaningSCOReport,
    circular_report: CircularReferenceReport,
    sorting_report: SortingReport,
    file_report: Optional[FileReport] = None
) -> OperationsReport:
    """Operation 6: Create comprehensive report"""
    return OperationsReport(
        expansion_report=expansion_report,
        cleaning_sco_report=sco_report,
        circular_reference_report=circular_report,
        sorting_report=sorting_report,
        file_report=file_report
    )


# =============================================================================
# Main Functions
# =============================================================================

def clean_stix_list(
    stix_list: List[StixObject], 
    clean_sco_fields: bool = False
) -> Tuple[List[StixObject], Union[CleanStixListSuccessReport, CleanStixListFailureReport]]:
    """
    Clean STIX objects in memory through 6-operation pipeline.
    
    Args:
        stix_list (List[StixObject]): Raw STIX objects requiring cleaning
        clean_sco_fields (bool): Whether to run SCO Field Cleaning operation (default: False)
    
    Returns:
        Tuple containing:
        - List[StixObject]: Processed and sorted STIX objects
        - Report: Success/failure report with detailed operation metrics
    """
    start_time = datetime.now()
    original_count = len(stix_list)
    
    try:
        # Make a deep copy to avoid modifying original data
        working_objects = deepcopy(stix_list)
        
        # Operation 1: Expansion Round 1
        working_objects, expansion_report = _operation_1_expansion_round_1(working_objects)
        
        # Operation 2: Expansion Round 2
        working_objects, expansion_report = _operation_2_expansion_round_2(working_objects, expansion_report)
        
        # Pruning Step: Remove unreferenced objects added during expansion  
        original_objects = deepcopy(stix_list)
        working_objects, _ = _prune_unreferenced_objects(working_objects, original_objects)
        
        # Update expansion report to reflect final object count after pruning
        expansion_report.number_of_objects_defined = len(working_objects)
        
        # Operation 3: SCO Cleaning (conditional)
        working_objects, sco_report = _operation_3_sco_cleaning(working_objects, clean_sco_fields)
        
        # Operation 4: Circular Reference Resolution
        working_objects, circular_report = _operation_4_circular_reference_resolution(working_objects)
        
        # Operation 5: Dependency Sorting
        working_objects, sorting_report = _operation_5_dependency_sorting(working_objects)
        
        # Operation 6: Comprehensive Reporting
        operations_report = _operation_6_comprehensive_reporting(
            expansion_report, sco_report, circular_report, sorting_report
        )
        
        # Create success report
        success_report = CleanStixListSuccessReport(
            report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            total_number_of_objects_processed=len(working_objects),
            clean_operation_outcome=True,
            return_message=f"Successfully processed {len(working_objects)} STIX objects (started with {original_count})",
            detailed_operation_reports=operations_report
        )
        
        return working_objects, success_report
        
    except Exception as e:
        # Create failure report
        # Try to create partial reports for completed operations
        try:
            # Create empty reports for failed operations
            empty_expansion = ExpansionReport(
                number_of_objects_defined=original_count,
                number_of_objects_referenced=0,
                missing_ids_list=[],
                sources_of_expansion=[]
            )
            empty_sco = CleaningSCOReport(
                number_of_scos_cleaned=0,
                list_of_stix_ids_where_created_field_was_removed=[],
                list_of_stix_ids_where_modified_field_was_removed=[],
                list_of_stix_ids_where_other_fields_were_removed=[]
            )
            empty_circular = CircularReferenceReport(
                number_of_circular_references_found=0,
                list_of_circular_reference_paths=[],
                deleted_fields_and_values=[]
            )
            empty_sorting = SortingReport(
                sorting_successful=False,
                sorted_list_of_stix_ids=[],
                diagram_of_sorted_dependencies="Failed to generate",
                unresolved_references=[]
            )
            
            operations_report = _operation_6_comprehensive_reporting(
                empty_expansion, empty_sco, empty_circular, empty_sorting
            )
        except:
            operations_report = None
        
        failure_report = CleanStixListFailureReport(
            report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            total_number_of_objects_processed=original_count,
            clean_operation_outcome=False,
            return_message=f"Failed to process STIX objects: {str(e)}",
            detailed_operation_reports=operations_report
        )
        
        return stix_list, failure_report


def clean_stix_directory(
    directory_path: str, 
    clean_sco_fields: bool = False
) -> List[Union[CleanStixListSuccessReport, CleanStixListFailureReport]]:
    """
    Process all JSON files in directory through cleaning pipeline with file organization.
    
    Args:
        directory_path (str): Target directory containing STIX JSON files
        clean_sco_fields (bool): Whether to run SCO Field Cleaning operation (default: False)
    
    Returns:
        List[Report]: Collection of processing reports (one per input file)
    
    File Organization:
        - Originals moved to: {directory_path}/original/
        - Reports saved to: {directory_path}/reports/
        - Cleaned bundles saved to: {directory_path}/ (root)
    """
    directory = Path(directory_path)
    if not directory.exists() or not directory.is_dir():
        raise ValueError(f"Directory does not exist: {directory_path}")
    
    # Create subdirectories
    original_dir = directory / "original"
    reports_dir = directory / "reports"
    original_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    
    # Find all JSON files
    json_files = list(directory.glob("*.json"))
    if not json_files:
        return []
    
    results = []
    file_reports = []
    
    for json_file in json_files:
        try:
            # Load JSON data
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert to STIX objects
            stix_objects = []
            if isinstance(data, dict) and data.get('type') == 'bundle':
                # STIX Bundle
                for obj_data in data.get('objects', []):
                    # Validate required fields before creating StixObject
                    if 'id' in obj_data and 'type' in obj_data:
                        stix_objects.append(StixObject(**obj_data))
                    else:
                        print(f"Warning: Skipping invalid STIX object missing required fields: {obj_data}")
            elif isinstance(data, list):
                # List of STIX objects
                for obj_data in data:
                    # Validate required fields before creating StixObject
                    if isinstance(obj_data, dict) and 'id' in obj_data and 'type' in obj_data:
                        stix_objects.append(StixObject(**obj_data))
                    else:
                        print(f"Warning: Skipping invalid STIX object missing required fields: {obj_data}")
            else:
                # Single STIX object
                if isinstance(data, dict) and 'id' in data and 'type' in data:
                    stix_objects.append(StixObject(**data))
                else:
                    print(f"Warning: Skipping invalid STIX object missing required fields: {data}")
                    stix_objects = []  # No valid objects
            
            # Skip processing if no valid STIX objects found
            if not stix_objects:
                raise ValueError(f"No valid STIX objects found in {json_file.name}")
            
            # Process objects
            cleaned_objects, report = clean_stix_list(stix_objects, clean_sco_fields)
            
            # Generate file paths
            original_name = json_file.name
            cleaned_name = json_file.name
            report_name = f"{json_file.stem}_report.json"
            
            original_path = original_dir / original_name
            cleaned_path = directory / cleaned_name
            report_path = reports_dir / report_name
            
            # Move original file
            shutil.move(str(json_file), str(original_path))
            
            # Create cleaned bundle
            bundle_id = f"bundle--{uuid.uuid4()}"
            cleaned_bundle = {
                "type": "bundle",
                "id": bundle_id,
                "objects": [obj.model_dump() for obj in cleaned_objects]
            }
            
            # Save cleaned bundle
            with open(cleaned_path, 'w', encoding='utf-8') as f:
                json.dump(cleaned_bundle, f, indent=2, ensure_ascii=False)
            
            # Save report
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report.model_dump(), f, indent=2, ensure_ascii=False)
            
            # Create file report entry
            single_file_report = SingleFileReport(
                original_file_name=original_name,
                original_file_path=str(original_path),
                updated_file_name=cleaned_name,
                updated_file_path=str(cleaned_path),
                report_file_name=report_name,
                report_file_path=str(report_path)
            )
            file_reports.append(single_file_report)
            
            # Update report with file information
            if isinstance(report, CleanStixListSuccessReport):
                report.detailed_operation_reports.file_report = FileReport(
                    number_of_files_processed=1,
                    list_of_processed_changes_per_file=[single_file_report]
                )
            
            results.append(report)
            
        except Exception as e:
            # Create failure report for this file
            failure_report = CleanStixListFailureReport(
                report_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_number_of_objects_processed=0,
                clean_operation_outcome=False,
                return_message=f"Failed to process file {json_file.name}: {str(e)}",
                detailed_operation_reports=OperationsReport(
                    expansion_report=ExpansionReport(
                        number_of_objects_defined=0,
                        number_of_objects_referenced=0,
                        missing_ids_list=[],
                        sources_of_expansion=[]
                    ),
                    cleaning_sco_report=CleaningSCOReport(
                        number_of_scos_cleaned=0,
                        list_of_stix_ids_where_created_field_was_removed=[],
                        list_of_stix_ids_where_modified_field_was_removed=[],
                        list_of_stix_ids_where_other_fields_were_removed=[]
                    ),
                    circular_reference_report=CircularReferenceReport(
                        number_of_circular_references_found=0,
                        list_of_circular_reference_paths=[],
                        deleted_fields_and_values=[]
                    ),
                    sorting_report=SortingReport(
                        sorting_successful=False,
                        sorted_list_of_stix_ids=[],
                        diagram_of_sorted_dependencies="Failed",
                        unresolved_references=[]
                    )
                )
            )
            results.append(failure_report)
    
    # Update all success reports with complete file information
    complete_file_report = FileReport(
        number_of_files_processed=len(file_reports),
        list_of_processed_changes_per_file=file_reports
    )
    
    for report in results:
        if isinstance(report, CleanStixListSuccessReport):
            report.detailed_operation_reports.file_report = complete_file_report
    
    return results
