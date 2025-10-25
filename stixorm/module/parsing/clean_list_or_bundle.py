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


class DeduplicationReport(BaseModel):
    """Report for object deduplication operations"""
    number_of_objects_before_deduplication: int
    number_of_objects_after_deduplication: int
    number_of_duplicates_removed: int
    list_of_duplicate_stix_ids: List[str]


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


class DeletedFieldAndValues(BaseModel):
    """Model for tracking deleted field information"""
    stix_id: str  # of the object where the field is deleted
    field_name: str  # field name deleted
    deleted_value: Union[str, List[str]]  # Stix_id or list of Stix_id's referenced by the deleted field


class OperationTiming(BaseModel):
    """Model for tracking operation timing"""
    operation_name: str
    start_time: str  # Format: "%Y-%m-%d %H:%M:%S.%f"
    end_time: str    # Format: "%Y-%m-%d %H:%M:%S.%f"
    duration_seconds: float


class CircularReferenceReport(BaseModel):
    """Report for circular reference resolution"""
    number_of_circular_references_found: int
    list_of_circular_reference_paths: List[List[str]]  # Each inner list represents a circular path
    deleted_fields_and_values: List[DeletedFieldAndValues]


class SortingReport(BaseModel):
    """Report for dependency sorting operations"""
    sorting_successful: bool
    sorted_list_of_stix_ids: List[str]
    diagram_of_sorted_dependencies: str  # String representation of dependency graph
    unresolved_references: List[str]


class ListReport(BaseModel):
    """Core operations report for processing a single STIX list"""
    deduplication_report: DeduplicationReport
    expansion_report: ExpansionReport
    cleaning_sco_report: CleaningSCOReport
    circular_reference_report: CircularReferenceReport
    sorting_report: SortingReport
    operation_timings: List[OperationTiming]  # Time measurements for each of the 7 operations
    total_processing_time_seconds: float  # Sum of all operation durations


class FileReport(BaseModel):
    """Report for directory processing containing ListReport + file metadata"""
    directory_path: str
    original_file_name: str
    original_file_path: str
    updated_file_name: str
    updated_file_path: str
    report_file_name: str
    report_file_path: str
    operations_report: ListReport
    total_processing_time_seconds: float


class CleanStixListSuccessReport(BaseModel):
    """Success report for STIX cleaning operations"""
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[True]
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]


class CleanStixListFailureReport(BaseModel):
    """Failure report for STIX cleaning operations"""
    report_date_time: str  # Format: "%Y-%m-%d %H:%M:%S"
    total_number_of_objects_processed: int
    clean_operation_outcome: Literal[False]
    return_message: str
    detailed_operation_reports: Union[FileReport, ListReport]


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
    """
    Extract all STIX ID references from a STIX object using dynamic detection.
    
    This function automatically detects:
    1. All fields ending with '_ref' or '_refs' 
    2. Any string value that matches STIX ID pattern (type--uuid)
    
    This approach is future-proof and works with any STIX extensions or custom objects.
    """
    references = set()
    
    def _is_valid_stix_id(value: str) -> bool:
        """Check if a string matches STIX ID pattern: type--uuid"""
        if not isinstance(value, str):
            return False
        
        # STIX ID pattern: must have exactly one '--' separator
        if value.count('--') != 1:
            return False
        
        # Split and validate format
        parts = value.split('--')
        if len(parts) != 2:
            return False
        
        stix_type, stix_uuid = parts
        
        # Validate type part (must be non-empty, alphanumeric with hyphens)
        if not stix_type or not all(c.isalnum() or c in '-_' for c in stix_type):
            return False
        
        # Validate UUID part (must be non-empty, UUID-like format)
        if not stix_uuid or len(stix_uuid) < 8:
            return False
        
        return True
    
    def _extract_from_data(data: Any, current_path: str = "") -> None:
        """Recursively extract references from any data structure"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_key_path = f"{current_path}.{key}" if current_path else key
                
                # Method 1: Check fields ending with _ref or _refs (standard STIX pattern)
                if key.endswith('_ref') or key.endswith('_refs'):
                    if isinstance(value, str) and _is_valid_stix_id(value):
                        references.add(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and _is_valid_stix_id(item):
                                references.add(item)
                
                # Method 2: Check ANY string value for STIX ID pattern (universal approach)
                elif isinstance(value, str) and _is_valid_stix_id(value):
                    # Exclude the object's own ID field - all other STIX IDs are potential references
                    if key != 'id':
                        references.add(value)
                
                # Continue recursive search
                _extract_from_data(value, current_key_path)
                
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_index_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                
                # Method 2: Check list items for STIX ID pattern
                if isinstance(item, str) and _is_valid_stix_id(item):
                    references.add(item)
                
                # Continue recursive search
                _extract_from_data(item, current_index_path)
    
    # Start extraction from root object
    _extract_from_data(obj)
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


def _topological_sort_with_dependencies(object_dependencies: List[Dict]) -> List[Dict]:
    """
    Perform topological sort using pre-computed dependencies.
    
    Args:
        object_dependencies: List of dicts with keys: 'object', 'dependencies', 'id'
    
    Returns:
        List of dependency objects in topologically sorted order
    """
    # Build dependency graph using pre-computed dependencies
    in_degree = defaultdict(int)
    adj_list = defaultdict(list)
    obj_dict = {item['id']: item for item in object_dependencies}
    all_ids = set(obj_dict.keys())
    
    print(f"DEBUG TOPO: Starting with {len(object_dependencies)} objects")
    
    # Initialize in-degree for all objects
    for obj_id in all_ids:
        in_degree[obj_id] = 0
    
    # Build the graph using pre-computed dependencies
    for item in object_dependencies:
        obj_id = item['id']
        dependencies = item['dependencies']
        
        # Debug specific sequences
        if obj_id in ["sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e", "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8"]:
            print(f"DEBUG GRAPH: {obj_id[:20]}... dependencies: {dependencies}")
        
        for dep_id in dependencies:
            if dep_id in all_ids:  # Only consider dependencies within our object set
                adj_list[dep_id].append(obj_id)  # dep_id must come before obj_id
                in_degree[obj_id] += 1
                
                if obj_id in ["sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e"] or dep_id in ["sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8"]:
                    print(f"DEBUG GRAPH: {obj_id[:20]}... depends on {dep_id[:20]}..., in_degree now {in_degree[obj_id]}")
    
    # Kahn's algorithm
    queue = [obj_id for obj_id in all_ids if in_degree[obj_id] == 0]
    sorted_objects = []
    
    print(f"DEBUG TOPO: Starting queue (in_degree=0): {[id[:20]+'...' for id in queue]}")
    
    while queue:
        current_id = queue.pop(0)
        sorted_objects.append(obj_dict[current_id])
        
        print(f"DEBUG TOPO: Processing {current_id[:20]}...")
        
        # Reduce in-degree of dependent objects
        for dependent_id in adj_list[current_id]:
            in_degree[dependent_id] -= 1
            if in_degree[dependent_id] == 0:
                queue.append(dependent_id)
                print(f"DEBUG TOPO: Added {dependent_id[:20]}... to queue (in_degree now 0)")
    
    if len(sorted_objects) != len(object_dependencies):
        print(f"DEBUG TOPO: Cycle detected! Got {len(sorted_objects)} of {len(object_dependencies)} objects")
        # Return remaining objects in original order
        remaining = [item for item in object_dependencies if item['id'] not in [obj['id'] for obj in sorted_objects]]
        sorted_objects.extend(remaining)
    
    print(f"DEBUG TOPO: Final order: {[obj['id'][:20]+'...' for obj in sorted_objects]}")
    return sorted_objects


def _topological_sort(objects: List[StixObject]) -> Tuple[List[str], List[str], bool]:
    """
    Legacy function for StixObject compatibility - converts to new format
    Returns: (sorted_ids, unresolved_refs, success)
    """
    # Convert StixObjects to dependency format
    object_dependencies = []
    for obj in objects:
        # Extract references from the StixObject
        references = _extract_references_from_object(obj.model_dump())
        object_dependencies.append({
            'object': obj,
            'dependencies': references,
            'id': obj.id
        })
    
    # Sort using new function
    sorted_deps = _topological_sort_with_dependencies(object_dependencies)
    
    # Extract just the IDs for legacy return format
    sorted_ids = [item['id'] for item in sorted_deps]
    unresolved_refs = []  # TODO: Calculate from sorting results
    success = len(sorted_ids) == len(objects)
    
    return sorted_ids, unresolved_refs, success


def _legacy_topological_sort(objects: List[StixObject]) -> Tuple[List[str], List[str], bool]:
    """
    Original topological sort implementation - kept for reference
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
    
    # Build graph and calculate in-degrees with debugging
    reference_map = {}  # Track what each object references
    for obj in objects:
        obj_data = obj.model_dump()
        references = _extract_references_from_object(obj_data)
        reference_map[obj.id] = references
        
        # Debug for sequence objects
        if obj.id in ["sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e", "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8"]:
            print(f"DEBUG GRAPH: {obj.id[:20]}... references: {references}")
        
        for ref_id in references:
            if ref_id in all_ids:  # Only consider internal references
                adj_list[ref_id].append(obj.id)
                in_degree[obj.id] += 1
                
                # Debug dependency relationships for sequences
                if obj.id in ["sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e"] or ref_id in ["sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8"]:
                    print(f"DEBUG GRAPH: {obj.id[:20]}... depends on {ref_id[:20]}..., in_degree now {in_degree[obj.id]}")
    
    # Debug problematic sequence objects  
    problem_sequences = [
        "sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e", 
        "sequence--fb97db29-be35-4f8d-b483-c2899750838d"
    ]
    
    target_sequences = [
        "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8",
        "sequence--4089e2b7-816d-4ad4-9d11-2604739b16ef"
    ]
    
    print(f"DEBUG TOPOLOGICAL SORT: Analyzing {len(objects)} objects")
    
    for seq_id in problem_sequences + target_sequences:
        if seq_id in all_ids:
            refs = reference_map.get(seq_id, set())
            print(f"DEBUG: {seq_id[:20]}... references: {refs}")
            print(f"DEBUG: {seq_id[:20]}... in_degree: {in_degree[seq_id]}")
            
            # Show raw object data for problem sequences to verify field detection
            if seq_id in problem_sequences:
                obj_data = obj_dict[seq_id].model_dump()
                print(f"DEBUG: {seq_id[:20]}... raw on_completion field: {obj_data.get('on_completion', 'NOT FOUND')}")
            
            # Check if referenced objects exist
            for ref in refs:
                if ref in all_ids:
                    print(f"DEBUG: Referenced object {ref[:20]}... exists in dataset")
                else:
                    print(f"DEBUG: Referenced object {ref[:20]}... MISSING from dataset")
    
    # Kahn's algorithm with enhanced tracking
    queue = deque([obj_id for obj_id in all_ids if in_degree[obj_id] == 0])
    sorted_ids = []
    
    print(f"DEBUG: Initial queue (in_degree=0): {list(queue)}")
    
    while queue:
        current = queue.popleft()
        sorted_ids.append(current)
        
        # Debug when we process the target sequences
        if current in ["sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8", "sequence--4089e2b7-816d-4ad4-9d11-2604739b16ef"]:
            print(f"DEBUG: Processing target sequence {current}, dependents: {adj_list[current]}")
        
        for neighbor in adj_list[current]:
            in_degree[neighbor] -= 1
            if neighbor in problem_sequences:
                print(f"DEBUG: Reduced in_degree for {neighbor} to {in_degree[neighbor]}")
            
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
                if neighbor in problem_sequences:
                    print(f"DEBUG: Added {neighbor} to queue (in_degree now 0)")
    
    # Check for cycles
    success = len(sorted_ids) == len(all_ids)
    unresolved_refs = [obj_id for obj_id in all_ids if in_degree[obj_id] > 0]
    
    if unresolved_refs:
        print(f"DEBUG: Unresolved objects: {unresolved_refs}")
        for unresolved in unresolved_refs:
            if unresolved in problem_sequences:
                print(f"DEBUG: Problem sequence {unresolved} final in_degree: {in_degree[unresolved]}")
                print(f"DEBUG: Problem sequence {unresolved} references: {reference_map.get(unresolved, set())}")
    
    return sorted_ids, unresolved_refs, success


def _create_dependency_diagram(objects: List[StixObject], sorted_ids: List[str]) -> str:
    """Create a string representation of the dependency graph from StixObjects"""
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


def _create_dependency_diagram_from_dicts(objects: List[Dict[str, Any]], sorted_ids: List[str]) -> str:
    """Create a string representation of the dependency graph from raw dictionaries"""
    lines = ["Dependency Diagram:", "=" * 50]
    
    obj_dict = {obj['id']: obj for obj in objects}
    
    for i, obj_id in enumerate(sorted_ids):
        obj = obj_dict[obj_id]
        references = _extract_references_from_object(obj)
        
        # Filter for internal references only
        internal_refs = [ref for ref in references if ref in obj_dict]
        
        indent = "  " * min(i // 5, 10)  # Progressive indentation
        if internal_refs:
            lines.append(f"{indent}{obj_id} ({obj['type']}) -> {len(internal_refs)} refs")
        else:
            lines.append(f"{indent}{obj_id} ({obj['type']}) [leaf]")
    
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

def _operation_1_object_deduplication(objects: List[StixObject]) -> Tuple[List[StixObject], DeduplicationReport]:
    """Operation 1: Remove duplicate STIX objects by ID"""
    original_count = len(objects)
    unique_objects = {}
    duplicate_ids = []
    
    # Track duplicates while maintaining order
    for obj in objects:
        if obj.id in unique_objects:
            duplicate_ids.append(obj.id)
        else:
            unique_objects[obj.id] = obj
    
    deduplicated_objects = list(unique_objects.values())
    final_count = len(deduplicated_objects)
    
    report = DeduplicationReport(
        number_of_objects_before_deduplication=original_count,
        number_of_objects_after_deduplication=final_count,
        number_of_duplicates_removed=original_count - final_count,
        list_of_duplicate_stix_ids=list(set(duplicate_ids))  # Remove duplicates from duplicates list
    )
    
    return deduplicated_objects, report


def _operation_2_check_dependencies_only(objects: List[StixObject]) -> Tuple[List[StixObject], ExpansionReport]:
    """Check for missing dependencies without enrichment from external sources"""
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
    
    # Create expansion report (no sources, just missing IDs)
    report = ExpansionReport(
        number_of_objects_defined=len(defined_ids),
        number_of_objects_referenced=len(all_references),
        missing_ids_list=list(missing_ids),
        sources_of_expansion=[]  # No external sources checked
    )
    
    return objects, report


def _operation_2_expansion_round_1(objects: List[StixObject]) -> Tuple[List[StixObject], ExpansionReport]:
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


def _operation_3_expansion_round_2(objects: List[StixObject], round_1_report: ExpansionReport) -> Tuple[List[StixObject], ExpansionReport]:
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


def _operation_4_sco_cleaning(objects: List[StixObject], clean_sco_fields: bool) -> Tuple[List[StixObject], CleaningSCOReport]:
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


def _operation_5_circular_reference_resolution(objects: List[StixObject]) -> Tuple[List[StixObject], CircularReferenceReport]:
    """Operation 4: Resolve circular references"""
    circular_paths = _detect_circular_references(objects)
    deleted_fields_and_values = []
    resolved_objects = []
    
    # Create a mapping for modifications
    obj_modifications = {obj.id: obj.model_dump() for obj in objects}
    
    for path in circular_paths:
        if len(path) == 2 and path[0] == path[1]:
            # Self-reference case
            obj_id = path[0]
            obj_data = obj_modifications[obj_id]
            
            # Remove self-referencing fields
            ref_fields = ['created_by_ref', 'object_marking_refs']
            for field in ref_fields:
                if field in obj_data:
                    value = obj_data[field]
                    if field == 'created_by_ref' and value == obj_id:
                        deleted_fields_and_values.append(DeletedFieldAndValues(
                            stix_id=obj_id,
                            field_name=field,
                            deleted_value=value
                        ))
                        del obj_data[field]
                    elif field == 'object_marking_refs' and isinstance(value, list) and obj_id in value:
                        new_value = [v for v in value if v != obj_id]
                        deleted_fields_and_values.append(DeletedFieldAndValues(
                            stix_id=obj_id,
                            field_name=field,
                            deleted_value=[obj_id]
                        ))
                        if new_value:
                            obj_data[field] = new_value
                        else:
                            del obj_data[field]
                
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
                    deleted_fields_and_values.append(DeletedFieldAndValues(
                        stix_id=obj1_id,
                        field_name='object_marking_refs',
                        deleted_value=[obj2_id]
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
                    deleted_fields_and_values.append(DeletedFieldAndValues(
                        stix_id=obj2_id,
                        field_name='object_marking_refs',
                        deleted_value=[obj1_id]
                    ))
                    if new_refs:
                        obj2_data['object_marking_refs'] = new_refs
                    else:
                        del obj2_data['object_marking_refs']
            # Check for Malware Behavior <-> Malware Method pattern
            elif obj1_type == 'malware-behavior' and obj2_type == 'malware-method':
                # Remove behavior_ref from malware method
                if 'behavior_ref' in obj2_data and obj2_data['behavior_ref'] == obj1_id:
                    deleted_fields_and_values.append(DeletedFieldAndValues(
                        stix_id=obj2_id,
                        field_name='behavior_ref',
                        deleted_value=obj1_id
                    ))
                    del obj2_data['behavior_ref']
            elif obj2_type == 'malware-behavior' and obj1_type == 'malware-method':
                # Remove behavior_ref from malware method
                if 'behavior_ref' in obj1_data and obj1_data['behavior_ref'] == obj2_id:
                    deleted_fields_and_values.append(DeletedFieldAndValues(
                        stix_id=obj1_id,
                        field_name='behavior_ref',
                        deleted_value=obj2_id
                    ))
                    del obj1_data['behavior_ref']
            else:
                # Generic bidirectional - remove created_by_ref from second object
                if 'created_by_ref' in obj2_data and obj2_data['created_by_ref'] == obj1_id:
                    deleted_fields_and_values.append(DeletedFieldAndValues(
                        stix_id=obj2_id,
                        field_name='created_by_ref',
                        deleted_value=obj1_id
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
        deleted_fields_and_values=deleted_fields_and_values
    )
    
    return resolved_objects, report


def _operation_6_dependency_sorting(objects: List[StixObject]) -> Tuple[List[StixObject], SortingReport]:
    """Operation 6: Sort StixObjects by dependency order using pre-computed dependencies"""
    print(f"DEBUG OP6: Starting dependency sorting with {len(objects)} objects")
    
    # Phase 1: Pre-compute dependencies for each StixObject
    object_dependencies = []
    for obj in objects:
        # Convert StixObject to dict for dependency extraction
        obj_dict = obj.model_dump()
        dependencies = _extract_references_from_object(obj_dict)
        object_dependencies.append({
            'object': obj,  # Keep as StixObject
            'dependencies': dependencies,
            'id': obj.id
        })
        
        # Debug specific objects
        if obj.id in ["sequence--5ced78bf-aab8-4650-9c9e-a6914d68b46e", "sequence--4c9100f2-06a1-4570-ba51-7dabde2371b8"]:
            print(f"DEBUG OP6: {obj.id[:20]}... pre-computed dependencies: {dependencies}")
    
    # Phase 2: Sort using computed dependencies
    sorted_deps = _topological_sort_with_dependencies(object_dependencies)
    
    # Extract sorted objects and metadata
    sorted_objects = [item['object'] for item in sorted_deps]  # These are StixObjects
    sorted_ids = [item['id'] for item in sorted_deps]
    success = len(sorted_objects) == len(objects)
    
    # Calculate unresolved references (dependencies not found in object set)
    all_ids = {obj.id for obj in objects}
    unresolved_refs = []
    for item in object_dependencies:
        for dep_id in item['dependencies']:
            if dep_id not in all_ids:
                unresolved_refs.append(dep_id)
    unresolved_refs = list(set(unresolved_refs))  # Remove duplicates
    
    # Create diagram using StixObjects
    if success:
        diagram = _create_dependency_diagram(sorted_objects, sorted_ids)
    else:
        diagram = "Sorting failed due to circular dependencies"
    
    print(f"DEBUG OP6: Completed sorting - success={success}, unresolved={len(unresolved_refs)}")
    
    report = SortingReport(
        sorting_successful=success,
        sorted_list_of_stix_ids=sorted_ids,
        diagram_of_sorted_dependencies=diagram,
        unresolved_references=unresolved_refs
    )
    
    return sorted_objects, report


def _operation_7_comprehensive_reporting(
    deduplication_report: DeduplicationReport,
    expansion_report: ExpansionReport,
    sco_report: CleaningSCOReport,
    circular_report: CircularReferenceReport,
    sorting_report: SortingReport,
    operation_timings: List[OperationTiming]
) -> ListReport:
    """Operation 7: Create comprehensive report for STIX list operations"""
    total_time = sum(timing.duration_seconds for timing in operation_timings)
    
    return ListReport(
        deduplication_report=deduplication_report,
        expansion_report=expansion_report,
        cleaning_sco_report=sco_report,
        circular_reference_report=circular_report,
        sorting_report=sorting_report,
        operation_timings=operation_timings,
        total_processing_time_seconds=total_time
    )


# =============================================================================
# Main Functions
# =============================================================================

def clean_stix_list(
    stix_list: List[Dict[str, Any]], 
    clean_sco_fields: bool = False,
    enrich_from_external_sources: bool = False
) -> Tuple[List[Dict[str, Any]], Union[CleanStixListSuccessReport, CleanStixListFailureReport]]:
    """
    Clean STIX objects in memory through 7-operation pipeline with conditional enrichment.
    Accepts raw dictionaries, converts to StixObjects internally, then returns dictionaries.
    
    Args:
        stix_list (List[Dict]): Raw STIX object dictionaries requiring cleaning
        clean_sco_fields (bool): Whether to run SCO Field Cleaning operation (default: False)
        enrich_from_external_sources (bool): Whether to fetch missing objects from external sources (default: False)
    
    Returns:
        Tuple containing:
        - List[Dict]: Processed and dependency-ordered STIX object dictionaries
        - Report: Success/failure report with detailed operation metrics
        
    When enrich_from_external_sources=False and missing dependencies are found:
        - Returns failure report with missing dependency IDs
        - No external sources are contacted
        - SCO cleaning and enrichment operations are skipped
    """
    start_time = datetime.now()
    original_count = len(stix_list)
    operation_timings = []
    
    try:
        # Convert raw dictionaries to StixObjects for internal processing
        stix_objects = []
        for obj_dict in stix_list:
            if isinstance(obj_dict, dict) and 'id' in obj_dict and 'type' in obj_dict:
                stix_objects.append(StixObject(**obj_dict))
            else:
                raise ValueError(f"Invalid STIX object missing required fields: {obj_dict}")
        
        # Make a deep copy to avoid modifying original data
        working_objects = deepcopy(stix_objects)
        
        # Operation 1: Object Deduplication
        op_start = datetime.now()
        working_objects, deduplication_report = _operation_1_object_deduplication(working_objects)
        op_end = datetime.now()
        operation_timings.append(OperationTiming(
            operation_name="Object Deduplication",
            start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
            end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
            duration_seconds=(op_end - op_start).total_seconds()
        ))
        
        # Operation 2: Expansion Round 1 (conditional)
        op_start = datetime.now()
        if enrich_from_external_sources:
            working_objects, expansion_report = _operation_2_expansion_round_1(working_objects)
        else:
            # Check for missing dependencies without enrichment
            working_objects, expansion_report = _operation_2_check_dependencies_only(working_objects)
            # If missing dependencies found, return failure
            if expansion_report.missing_ids_list:
                op_end = datetime.now()
                operation_timings.append(OperationTiming(
                    operation_name="Dependency Check (No Enrichment)",
                    start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    duration_seconds=(op_end - op_start).total_seconds()
                ))
                
                # Convert working objects back to dictionaries
                result_dicts = [obj.model_dump() for obj in working_objects]
                
                # Create failure report  
                list_report = ListReport(
                    deduplication_report=deduplication_report,
                    expansion_report=expansion_report,
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
                        diagram_of_sorted_dependencies="",
                        unresolved_references=[]
                    ),
                    operation_timings=operation_timings,
                    total_processing_time_seconds=(datetime.now() - start_time).total_seconds()
                )
                
                failure_report = CleanStixListFailureReport(
                    report_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    total_number_of_objects_processed=original_count,
                    clean_operation_outcome=False,
                    return_message=f"Missing dependencies found (enrichment disabled): {', '.join(expansion_report.missing_ids_list[:10])}{'...' if len(expansion_report.missing_ids_list) > 10 else ''}",
                    detailed_operation_reports=list_report
                )
                
                return result_dicts, failure_report
        
        op_end = datetime.now()
        operation_timings.append(OperationTiming(
            operation_name="Object Expansion Round 1" if enrich_from_external_sources else "Dependency Check (No Enrichment)",
            start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
            end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
            duration_seconds=(op_end - op_start).total_seconds()
        ))
        
        # Operation 3: Expansion Round 2 (conditional)
        if enrich_from_external_sources:
            op_start = datetime.now()
            working_objects, expansion_report = _operation_3_expansion_round_2(working_objects, expansion_report)
            op_end = datetime.now()
            operation_timings.append(OperationTiming(
                operation_name="Object Expansion Round 2",
                start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
                end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
                duration_seconds=(op_end - op_start).total_seconds()
            ))
            
            # Pruning Step: Remove unreferenced objects added during expansion  
            # Use the converted StixObjects, not the original dictionaries
            original_objects = deepcopy(stix_objects)
            working_objects, _ = _prune_unreferenced_objects(working_objects, original_objects)
            
            # Update expansion report to reflect final object count after pruning
            expansion_report.number_of_objects_defined = len(working_objects)
        
        # Operation 4: SCO Cleaning (conditional)
        op_start = datetime.now()
        working_objects, sco_report = _operation_4_sco_cleaning(working_objects, clean_sco_fields)
        op_end = datetime.now()
        operation_timings.append(OperationTiming(
            operation_name="SCO Field Cleaning",
            start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
            end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
            duration_seconds=(op_end - op_start).total_seconds()
        ))
        
        # Operation 5: Circular Reference Resolution
        op_start = datetime.now()
        working_objects, circular_report = _operation_5_circular_reference_resolution(working_objects)
        op_end = datetime.now()
        operation_timings.append(OperationTiming(
            operation_name="Circular Reference Resolution",
            start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
            end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
            duration_seconds=(op_end - op_start).total_seconds()
        ))
        
        # Operation 6: Dependency Sorting
        op_start = datetime.now()
        working_objects, sorting_report = _operation_6_dependency_sorting(working_objects)
        op_end = datetime.now()
        operation_timings.append(OperationTiming(
            operation_name="Dependency Sorting",
            start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
            end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
            duration_seconds=(op_end - op_start).total_seconds()
        ))
        
        # Operation 7: Comprehensive Reporting
        op_start = datetime.now()
        list_report = _operation_7_comprehensive_reporting(
            deduplication_report, expansion_report, sco_report, circular_report, sorting_report, operation_timings
        )
        op_end = datetime.now()
        operation_timings.append(OperationTiming(
            operation_name="Comprehensive Reporting",
            start_time=op_start.strftime("%Y-%m-%d %H:%M:%S.%f"),
            end_time=op_end.strftime("%Y-%m-%d %H:%M:%S.%f"),
            duration_seconds=(op_end - op_start).total_seconds()
        ))
        
        # Create success report
        success_report = CleanStixListSuccessReport(
            report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            total_number_of_objects_processed=len(working_objects),
            clean_operation_outcome=True,
            return_message=f"Successfully processed {len(working_objects)} STIX objects (started with {original_count})",
            detailed_operation_reports=list_report
        )
        
        # Convert StixObjects back to dictionaries for return
        result_dicts = []
        for obj in working_objects:
            if isinstance(obj, StixObject):
                result_dicts.append(obj.model_dump())
            else:
                # This shouldn't happen, but handle gracefully
                result_dicts.append(obj)
        
        return result_dicts, success_report
        
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
            
            # Create empty timing records for failed operations
            empty_timings = [OperationTiming(
                operation_name="Failed Operations",
                start_time=start_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                duration_seconds=0.0
            )]
            
            empty_deduplication = DeduplicationReport(
                number_of_objects_before_deduplication=original_count,
                number_of_objects_after_deduplication=original_count,
                number_of_duplicates_removed=0,
                list_of_duplicate_stix_ids=[]
            )
            
            list_report = _operation_7_comprehensive_reporting(
                empty_deduplication, empty_expansion, empty_sco, empty_circular, empty_sorting, empty_timings
            )
        except Exception:
            # Create minimal list report for complete failure
            list_report = ListReport(
                deduplication_report=DeduplicationReport(
                    number_of_objects_before_deduplication=original_count,
                    number_of_objects_after_deduplication=original_count,
                    number_of_duplicates_removed=0,
                    list_of_duplicate_stix_ids=[]
                ),
                expansion_report=ExpansionReport(
                    number_of_objects_defined=original_count,
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
                    diagram_of_sorted_dependencies="Failed to generate",
                    unresolved_references=[]
                ),
                operation_timings=[],
                total_processing_time_seconds=0.0
            )
        
        failure_report = CleanStixListFailureReport(
            report_date_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            total_number_of_objects_processed=original_count,
            clean_operation_outcome=False,
            return_message=f"Failed to process STIX objects: {str(e)}",
            detailed_operation_reports=list_report
        )
        
        return stix_list, failure_report


def clean_stix_directory(
    directory_path: str, 
    clean_sco_fields: bool = False,
    enrich_from_external_sources: bool = False
) -> List[Union[CleanStixListSuccessReport, CleanStixListFailureReport]]:
    """
    Process all JSON files in directory through cleaning pipeline with file organization.
    
    Args:
        directory_path (str): Target directory containing STIX JSON files
        clean_sco_fields (bool): Whether to run SCO Field Cleaning operation (default: False)
        enrich_from_external_sources (bool): Whether to fetch missing objects from external sources (default: False)
    
    Returns:
        List[Report]: Collection of processing reports (one per input file)
    
    File Organization:
        - Originals moved to: {directory_path}/original/
        - Reports saved to: {directory_path}/reports/
        - Cleaned bundles saved to: {directory_path}/ (root)
        
    When enrich_from_external_sources=False and missing dependencies are found:
        - Returns failure report with missing dependency IDs
        - No external sources are contacted
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
            cleaned_objects, report = clean_stix_list(stix_objects, clean_sco_fields, enrich_from_external_sources)
            
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
            
            # Create FileReport with embedded ListReport
            if isinstance(report, CleanStixListSuccessReport):
                file_start = datetime.now()
                file_report = FileReport(
                    directory_path=str(directory),
                    original_file_name=original_name,
                    original_file_path=str(original_path),
                    updated_file_name=cleaned_name,
                    updated_file_path=str(cleaned_path),
                    report_file_name=report_name,
                    report_file_path=str(report_path),
                    operations_report=report.detailed_operation_reports,
                    total_processing_time_seconds=report.detailed_operation_reports.total_processing_time_seconds + (datetime.now() - file_start).total_seconds()
                )
                
                # Update the report to use FileReport instead of ListReport
                report.detailed_operation_reports = file_report
            
            results.append(report)
            
        except Exception as e:
            # Create failure report for this file
            # Create minimal reports for failure
            empty_list_report = ListReport(
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
                ),
                operation_timings=[],
                total_processing_time_seconds=0.0
            )
            
            failure_report = CleanStixListFailureReport(
                report_date_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_number_of_objects_processed=0,
                clean_operation_outcome=False,
                return_message=f"Failed to process file {json_file.name}: {str(e)}",
                detailed_operation_reports=empty_list_report
            )
            results.append(failure_report)
    
    # Each report now contains its own FileReport with embedded ListReport
    
    return results
